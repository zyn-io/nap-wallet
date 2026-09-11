//! Reference prices for bridged pairs.
//!
//! A pool of a bridged asset is a slow mirror of a market elsewhere, and
//! the fee that protects its LPs from arbitrage is `√r − 1` for a
//! divergence `r` between the pool and that market (DECISIONS §5.7). This
//! module is where the market's side of `r` comes from: public price
//! sources, read by the operator, aggregated, and posted to the chain as
//! `UpdateReference { pool, price }`.
//!
//! What the chain does with it is bounded by construction: a reference sets
//! the **fee** and never the quote (`vm::effective_fee`), so a wrong or
//! manipulated number can make fees wrong and cannot move a unit out of a
//! pool. That is why keyless public endpoints are acceptable here where
//! they never would be for a price oracle — and why several are read and
//! the median taken, with a refusal to post when they disagree.
//!
//! Sources, none needing a key:
//!
//! | source | for | endpoint |
//! |---|---|---|
//! | Coinbase | crypto and the big stables | `api.coinbase.com/v2/prices/X-USD/spot` |
//! | CoinGecko | crypto, RWA tokens (tokenised treasuries, gold) | `api.coingecko.com/api/v3/simple/price` |
//! | Nasdaq | stocks and ETFs (last sale, delayed) | `api.nasdaq.com/api/quote/X/info?assetclass=stocks` |
//! | Yahoo | stocks and ETFs, fallback | `query1.finance.yahoo.com/v8/finance/chart/X` |
//! | Frankfurter (ECB) | fiat | `api.frankfurter.app/latest?from=EUR&to=USD` |
//! | Chainlink on Robinhood Chain | Robinhood's tokenised stocks and ETFs | `eth_call latestRoundData()` on the feed proxy, over the chain's public RPC |
//! | Robinhood token multiplier | the same tokens, from the share price | `eth_call uiMultiplier()` on the token × Nasdaq/Yahoo share price |
//!
//! Tokenised stocks are priced as the **token**, not the share: a Robinhood
//! stock token reinvests dividends through a multiplier, so it drifts above
//! the share price on purpose. Its Chainlink feed already quotes the token;
//! the share-price sources are scaled by `uiMultiplier()` to agree. The
//! registry of tokens and feeds is data (`data/robinhood-*.tsv`), and an
//! asset bridged from Robinhood Chain (origin `ORIGIN_ROBINHOOD_CHAIN`) is
//! priced as `RH:<SYM>`, never confused with the bare share.
//!
//! Everything is priced in USD first; a pool's reference is
//! `usd(asset0) / usd(asset1)`, in units of asset1 per unit of asset0, the
//! orientation `Reference.price` and `amm::spot_price` share.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::PoolId;
use swapvm::Fixed;
use zyn::node::Node;

/// Where one number comes from.
#[derive(Clone, PartialEq, Debug)]
pub enum Source {
    Coinbase(String),
    CoinGecko(String),
    Nasdaq(String),
    Yahoo(String),
    Frankfurter(String),
    /// A constant, for the unit of account itself.
    Constant(f64),
    /// A Chainlink `AggregatorV3` feed on an EVM chain: `(rpc url, feed
    /// proxy, heartbeat seconds)`. Stale beyond three heartbeats is refused.
    Chainlink(String, String, u64),
    /// A share-price source scaled by a Robinhood stock token's on-chain
    /// `uiMultiplier()`: `(rpc url, token contract, the share source)`.
    Scaled(String, String, Box<Source>),
}

impl Source {
    pub fn name(&self) -> &'static str {
        match self {
            Source::Coinbase(_) => "coinbase",
            Source::CoinGecko(_) => "coingecko",
            Source::Nasdaq(_) => "nasdaq",
            Source::Yahoo(_) => "yahoo",
            Source::Frankfurter(_) => "frankfurter",
            Source::Constant(_) => "constant",
            Source::Chainlink(..) => "chainlink",
            Source::Scaled(..) => "scaled",
        }
    }

    /// `coinbase:BTC`, `coingecko:bitcoin`, `nasdaq:AAPL`, `yahoo:AAPL`,
    /// `frankfurter:EUR`, `constant:1`.
    pub fn parse(s: &str) -> Option<Source> {
        let (kind, id) = s.split_once(':')?;
        let id = id.trim().to_string();
        Some(match kind.trim().to_ascii_lowercase().as_str() {
            "coinbase" => Source::Coinbase(id),
            "coingecko" => Source::CoinGecko(id),
            "nasdaq" => Source::Nasdaq(id),
            "yahoo" => Source::Yahoo(id),
            "frankfurter" => Source::Frankfurter(id),
            "constant" => Source::Constant(id.parse().ok()?),
            // chainlink:<feed>@<rpc>  — heartbeat defaults to a day
            "chainlink" => { let (feed, rpc) = id.split_once('@')?; Source::Chainlink(rpc.to_string(), feed.to_string(), 86_400) }
            _ => return None,
        })
    }
}

/// The symbols we know how to price, and where. Overridable per symbol
/// with `ZYN_FEED_MAP="SYM=source:id|source:id,SYM2=…"`.
pub fn default_map() -> BTreeMap<String, Vec<Source>> {
    let mut m: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    let cb = |s: &str| Source::Coinbase(s.to_string());
    let cg = |s: &str| Source::CoinGecko(s.to_string());
    let nq = |s: &str| Source::Nasdaq(s.to_string());
    let ya = |s: &str| Source::Yahoo(s.to_string());
    // Crypto.
    for (sym, gecko) in [("BTC", "bitcoin"), ("ETH", "ethereum"), ("SOL", "solana"), ("ZEC", "zcash"), ("LINK", "chainlink"), ("AVAX", "avalanche-2"), ("LTC", "litecoin"), ("XRP", "ripple"), ("DOGE", "dogecoin"), ("ADA", "cardano"), ("DOT", "polkadot"), ("NEAR", "near"), ("ATOM", "cosmos"), ("TON", "the-open-network"), ("SUI", "sui"), ("APT", "aptos")] {
        m.insert(sym.into(), vec![cb(sym), cg(gecko)]);
    }
    // Stables. USD itself is the unit; the others are quoted, because a
    // depeg is exactly the moment a reference matters.
    m.insert("USD".into(), vec![Source::Constant(1.0)]);
    for (sym, gecko) in [("USDC", "usd-coin"), ("USDT", "tether"), ("DAI", "dai"), ("EURC", "euro-coin"), ("PYUSD", "paypal-usd"), ("USDS", "usds"), ("FDUSD", "first-digital-usd")] {
        m.insert(sym.into(), vec![cb(sym), cg(gecko)]);
    }
    // RWA tokens: tokenised treasuries and gold. CoinGecko ids; override if
    // an id turns out to have moved.
    for (sym, gecko) in [("USDY", "ondo-us-dollar-yield"), ("OUSG", "ousg"), ("BUIDL", "blackrock-usd-institutional-digital-liquidity-fund"), ("USTB", "superstate-short-duration-us-government-securities-fund-ustb"), ("TBILL", "openeden-tbill"), ("XAUT", "tether-gold")] {
        m.insert(sym.into(), vec![cg(gecko)]);
    }
    m.insert("PAXG".into(), vec![cb("PAXG"), cg("pax-gold")]);
    // Fiat.
    for f in ["EUR", "GBP", "JPY", "CHF", "CAD", "AUD"] {
        m.insert(f.into(), vec![Source::Frankfurter(f.into())]);
    }
    // Stocks and ETFs: two independent readers of the same tape.
    for s in ["AAPL", "TSLA", "NVDA", "MSFT", "AMZN", "GOOGL", "META", "COIN", "MSTR", "HOOD", "NFLX", "AMD", "SPY", "QQQ", "IWM", "GLD", "SLV", "TLT", "IBIT", "ETHA", "VOO"] {
        m.insert(s.into(), vec![nq(s), ya(s)]);
    }
    // Every share behind a tokenised stock is also a bare share we can price.
    for (_, sym) in tokenized_stocks().keys() {
        m.entry(sym.clone()).or_insert_with(|| vec![nq(sym), ya(sym)]);
    }
    for sym in robinhood_tokens().keys() {
        m.entry(sym.clone()).or_insert_with(|| vec![nq(sym), ya(sym)]);
    }
    add_tokenized(&mut m, ROBINHOOD_RPC);
    m
}

pub const ROBINHOOD_RPC: &str = "https://rpc.mainnet.chain.robinhood.com";
const TOKENIZED: &str = include_str!("../data/tokenized-stocks.tsv");

/// Every tokenised stock CoinGecko knows, by issuer: `(issuer, underlying
/// symbol) → coingecko id`. Issuers: `X` xStocks (Backed), `ON` Ondo,
/// `RH` Robinhood, `D` Dinari.
pub fn tokenized_stocks() -> BTreeMap<(String, String), String> {
    TOKENIZED.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).filter_map(|l| {
        let mut it = l.split('\t');
        Some(((it.next()?.to_string(), it.next()?.to_string()), it.next()?.to_string()))
    }).collect()
}
const ROBINHOOD_TOKENS: &str = include_str!("../data/robinhood-stock-tokens.tsv");
const ROBINHOOD_FEEDS: &str = include_str!("../data/robinhood-chainlink-feeds.tsv");

/// Robinhood Chain's stock tokens: symbol → (token contract, name).
pub fn robinhood_tokens() -> BTreeMap<String, (String, String)> {
    ROBINHOOD_TOKENS.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).filter_map(|l| {
        let mut it = l.split('\t');
        Some((it.next()?.to_string(), (it.next()?.to_string(), it.next().unwrap_or("").to_string())))
    }).collect()
}

/// The Chainlink feeds Robinhood publishes for some of those tokens:
/// symbol → (feed proxy, decimals, heartbeat).
pub fn robinhood_feeds() -> BTreeMap<String, (String, u8, u64)> {
    ROBINHOOD_FEEDS.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).filter_map(|l| {
        let mut it = l.split('\t');
        Some((it.next()?.to_string(), (it.next()?.to_string(), it.next()?.parse().ok()?, it.next()?.parse().ok()?)))
    }).collect()
}

/// Add every tokenised stock under its issuer's namespace.
///
/// - `RH:<SYM>` (Robinhood Chain): the Chainlink feed where there is one,
///   CoinGecko's token price, and the share price scaled by the token's
///   on-chain multiplier from Nasdaq and Yahoo — the token reinvests
///   dividends, so it is priced as the token.
/// - `X:<SYM>` (xStocks), `ON:<SYM>` (Ondo), `D:<SYM>` (Dinari): one token
///   is one share, so CoinGecko's token price alongside the share price
///   from Nasdaq and Yahoo.
pub fn add_tokenized(map: &mut BTreeMap<String, Vec<Source>>, rpc: &str) {
    let feeds = robinhood_feeds();
    let rh = robinhood_tokens();
    let cg = tokenized_stocks();
    for ((issuer, sym), id) in &cg {
        let mut v = Vec::new();
        if issuer == "RH" {
            if let Some((feed, _, hb)) = feeds.get(sym) {
                v.push(Source::Chainlink(rpc.to_string(), feed.clone(), *hb));
            }
            v.push(Source::CoinGecko(id.clone()));
            if let Some((token, _)) = rh.get(sym) {
                v.push(Source::Scaled(rpc.to_string(), token.clone(), Box::new(Source::Nasdaq(sym.clone()))));
                v.push(Source::Scaled(rpc.to_string(), token.clone(), Box::new(Source::Yahoo(sym.clone()))));
            }
        } else {
            v.push(Source::CoinGecko(id.clone()));
            v.push(Source::Nasdaq(sym.clone()));
            v.push(Source::Yahoo(sym.clone()));
        }
        map.insert(format!("{}:{}", issuer, sym), v);
    }
    // Robinhood tokens the registry lists but CoinGecko does not yet.
    for (sym, (token, _)) in rh {
        map.entry(format!("RH:{}", sym)).or_insert_with(|| {
            let mut v = Vec::new();
            if let Some((feed, _, hb)) = feeds.get(&sym) { v.push(Source::Chainlink(rpc.to_string(), feed.clone(), *hb)); }
            v.push(Source::Scaled(rpc.to_string(), token.clone(), Box::new(Source::Nasdaq(sym.clone()))));
            v.push(Source::Scaled(rpc.to_string(), token.clone(), Box::new(Source::Yahoo(sym.clone()))));
            v
        });
    }
}

/// Apply `SYM=source:id|source:id,…` on top of a map.
pub fn apply_overrides(map: &mut BTreeMap<String, Vec<Source>>, spec: &str) -> Result<(), String> {
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (sym, srcs) = entry.split_once('=').ok_or_else(|| format!("bad feed entry: {}", entry))?;
        let list: Result<Vec<Source>, String> = srcs.split('|').map(|s| Source::parse(s).ok_or_else(|| format!("bad source: {}", s))).collect();
        map.insert(sym.trim().to_ascii_uppercase(), list?);
    }
    Ok(())
}

/// The market symbol behind a Zyn asset symbol.
///
/// `SOL.zy` → `SOL`. Tokenised stocks carry their issuer's decoration —
/// `TSLAx` (xStocks), `bTSLA` (Backed), `wBTC` — which is stripped when the
/// bare symbol is one we know. Returns `None` for a symbol with no market
/// (a memecoin launched here, an LP share).
pub fn base_symbol(zyn_symbol: &str, known: &BTreeMap<String, Vec<Source>>) -> Option<String> {
    base_symbol_from(zyn_symbol, 0, known)
}

/// As [`base_symbol`], knowing where the asset was bridged from. A token
/// from Robinhood Chain is the token, `RH:<SYM>`, not the share.
pub fn base_symbol_from(zyn_symbol: &str, origin: u16, known: &BTreeMap<String, Vec<Source>>) -> Option<String> {
    let s = zyn_symbol.trim_end_matches(".zy");
    if origin == zyn_bridge::evm::ORIGIN_ROBINHOOD_CHAIN {
        let rh = format!("RH:{}", s.to_ascii_uppercase());
        if known.contains_key(&rh) { return Some(rh) }
    }
    // Issuer decorations name the token, and the token is what is priced:
    // `TSLAx` is xStocks, `TSLAon` is Ondo, `TSLA.d` / `dTSLA` is Dinari.
    let up = s.to_ascii_uppercase();
    for (suffix, issuer) in [("X", "X"), ("ON", "ON"), (".D", "D")] {
        if let Some(rest) = up.strip_suffix(suffix) {
            let key = format!("{}:{}", issuer, rest);
            if known.contains_key(&key) { return Some(key) }
        }
    }
    if let Some(rest) = s.strip_prefix('d') {
        let key = format!("D:{}", rest.to_ascii_uppercase());
        if known.contains_key(&key) { return Some(key) }
    }
    let up = s.to_ascii_uppercase();
    if known.contains_key(&up) {
        return Some(up);
    }
    if let Some(rest) = s.strip_suffix('x') {
        let up = rest.to_ascii_uppercase();
        if known.contains_key(&up) { return Some(up) }
    }
    for prefix in ['b', 'w', 'x', 'o'] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let up = rest.to_ascii_uppercase();
            if known.contains_key(&up) { return Some(up) }
        }
    }
    None
}

/// Median of what the sources said, or nothing if they disagree by more
/// than `max_spread` (a fraction): a reference that two readers cannot
/// agree on is not posted.
pub fn aggregate(mut samples: Vec<f64>, max_spread: f64) -> Option<f64> {
    samples.retain(|x| x.is_finite() && *x > 0.0);
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let (lo, hi) = (samples[0], samples[samples.len() - 1]);
    if (hi - lo) / lo > max_spread {
        return None;
    }
    let n = samples.len();
    Some(if n % 2 == 1 { samples[n / 2] } else { (samples[n / 2 - 1] + samples[n / 2]) / 2.0 })
}

/// A price as the chain takes it: 18 decimals, rounded to nearest.
pub fn to_fixed(x: f64) -> Option<Fixed> {
    if !x.is_finite() || x <= 0.0 || x > 1e20 {
        return None;
    }
    Some(Fixed::raw((x * 1e18).round() as i128))
}

/// Something that answers a source. The real one speaks HTTP; tests do not.
pub trait Fetcher {
    fn fetch(&self, source: &Source) -> Result<f64, String>;
    /// Called once per cycle with every CoinGecko id about to be asked for,
    /// so an implementation can fetch them in one request. Optional.
    fn prime(&self, _coingecko_ids: &[String]) {}
}

// ---------------------------------------------------------------------------
// Parsers, separated from transport so they can be tested on fixtures
// ---------------------------------------------------------------------------

pub fn parse_coinbase(body: &str) -> Result<f64, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.get("data").and_then(|d| d.get("amount")).and_then(|a| a.as_str()).and_then(|s| s.parse().ok()).ok_or_else(|| "no amount".into())
}

pub fn parse_coingecko(body: &str, id: &str) -> Result<f64, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.get(id).and_then(|d| d.get("usd")).and_then(|a| a.as_f64()).ok_or_else(|| format!("no usd price for {}", id))
}

/// Nasdaq's quote: `data.primaryData.lastSalePrice` as `"$319.97"`.
pub fn parse_nasdaq(body: &str) -> Result<f64, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let s = v.pointer("/data/primaryData/lastSalePrice").and_then(|p| p.as_str()).ok_or("no lastSalePrice")?;
    let cleaned: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
    cleaned.parse().map_err(|_| format!("no price ({})", s))
}

pub fn parse_yahoo(body: &str) -> Result<f64, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.pointer("/chart/result/0/meta/regularMarketPrice").and_then(|p| p.as_f64()).ok_or_else(|| "no regularMarketPrice".into())
}

/// One `eth_call` over JSON-RPC, returning the raw return data.
pub fn eth_call(get_post: &dyn Fn(&str, &str) -> Result<String, String>, rpc: &str, to: &str, data: &str) -> Result<Vec<u8>, String> {
    let req = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{{"to":"{}","data":"{}"}},"latest"]}}"#, to, data);
    let body = get_post(rpc, &req)?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    if let Some(err) = v.get("error") { return Err(format!("rpc error: {}", err)) }
    let hex = v.get("result").and_then(|r| r.as_str()).ok_or("no result")?;
    let hex = hex.trim_start_matches("0x");
    (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())).collect()
}

fn word_i128(ret: &[u8], i: usize) -> Result<i128, String> {
    let w = ret.get(i * 32..i * 32 + 32).ok_or("short return data")?;
    // Values here are far below 2^127; read the low 16 bytes, sign from the top.
    let neg = w[0] & 0x80 != 0;
    let mut v = 0i128;
    for b in &w[16..] { v = (v << 8) | *b as i128; }
    Ok(if neg { -v } else { v })
}

/// Decode `latestRoundData()`: `(answer, updatedAt)`.
pub fn decode_round(ret: &[u8]) -> Result<(i128, u64), String> {
    Ok((word_i128(ret, 1)?, word_i128(ret, 3)? as u64))
}

pub fn parse_frankfurter(body: &str) -> Result<f64, String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    v.pointer("/rates/USD").and_then(|p| p.as_f64()).ok_or_else(|| "no USD rate".into())
}

/// The HTTP fetcher. Short timeouts: a slow source is a missing sample,
/// not a stalled cycle. CoinGecko ids are fetched in one batch per cycle
/// (its free tier allows a few dozen requests a minute, not one per symbol).
#[derive(Default)]
pub struct Http {
    coingecko: std::sync::Mutex<BTreeMap<String, f64>>,
}

impl Fetcher for Http {
    fn prime(&self, ids: &[String]) {
        if ids.is_empty() { return }
        let mut fresh = BTreeMap::new();
        for chunk in ids.chunks(50) {
            let url = format!("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd", chunk.join(","));
            let body = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(10)).build()
                .get(&url).set("User-Agent", "Mozilla/5.0 (zynzapd-feeds)").set("Accept", "application/json").call().ok().and_then(|r| r.into_string().ok());
            let Some(body) = body else { continue };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                for id in chunk {
                    if let Some(px) = v.get(id).and_then(|d| d.get("usd")).and_then(|a| a.as_f64()) { fresh.insert(id.clone(), px); }
                }
            }
        }
        if let Ok(mut c) = self.coingecko.lock() { *c = fresh; }
    }

    fn fetch(&self, source: &Source) -> Result<f64, String> {
        if let Source::CoinGecko(id) = source {
            if let Some(px) = self.coingecko.lock().ok().and_then(|c| c.get(id).copied()) { return Ok(px) }
        }
        let get = |url: &str| -> Result<String, String> {
            ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(8)).build()
                .get(url).set("User-Agent", "Mozilla/5.0 (zynzapd-feeds)").set("Accept", "application/json, text/plain, */*").call().map_err(|e| e.to_string())?
                .into_string().map_err(|e| e.to_string())
        };
        let post = |url: &str, body: &str| -> Result<String, String> {
            ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(8)).build()
                .post(url).set("Content-Type", "application/json").send_string(body).map_err(|e| e.to_string())?
                .into_string().map_err(|e| e.to_string())
        };
        match source {
            Source::Chainlink(rpc, feed, heartbeat) => {
                let ret = eth_call(&post, rpc, feed, "0xfeaf968c")?;
                let (answer, updated) = decode_round(&ret)?;
                let dec = eth_call(&post, rpc, feed, "0x313ce567").and_then(|r| word_i128(&r, 0)).unwrap_or(8) as i32;
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                // Stock feeds publish 24/5; a weekend is two heartbeats of silence.
                if now.saturating_sub(updated) > heartbeat * 3 { return Err(format!("stale: updated {} s ago", now.saturating_sub(updated))) }
                if answer <= 0 { return Err("non-positive answer".into()) }
                Ok(answer as f64 / 10f64.powi(dec))
            }
            Source::Scaled(rpc, token, inner) => {
                let share = self.fetch(inner)?;
                let ret = eth_call(&post, rpc, token, "0xa60bf13d")?;
                let mult = word_i128(&ret, 0)? as f64 / 1e18;
                if !(0.1..=100.0).contains(&mult) { return Err(format!("implausible multiplier {}", mult)) }
                Ok(share * mult)
            }
            Source::Coinbase(sym) => parse_coinbase(&get(&format!("https://api.coinbase.com/v2/prices/{}-USD/spot", sym))?),
            Source::CoinGecko(id) => parse_coingecko(&get(&format!("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd", id))?, id),
            Source::Nasdaq(sym) => {
                // A stock or an ETF; the endpoint wants to be told which.
                let stocks = get(&format!("https://api.nasdaq.com/api/quote/{}/info?assetclass=stocks", sym)).and_then(|b| parse_nasdaq(&b));
                match stocks {
                    Ok(x) => Ok(x),
                    Err(_) => parse_nasdaq(&get(&format!("https://api.nasdaq.com/api/quote/{}/info?assetclass=etf", sym))?),
                }
            }
            Source::Yahoo(sym) => parse_yahoo(&get(&format!("https://query1.finance.yahoo.com/v8/finance/chart/{}?range=1d&interval=1d", sym))?),
            Source::Frankfurter(cur) => parse_frankfurter(&get(&format!("https://api.frankfurter.app/latest?from={}&to=USD", cur))?),
            Source::Constant(x) => Ok(*x),
        }
    }
}

// ---------------------------------------------------------------------------
// The feed
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FeedConfig {
    pub interval_secs: u64,
    /// Post when the reference moved by more than this, in basis points.
    pub move_bps: u64,
    /// Post anyway after this long, so freshness never lapses on a quiet pool.
    pub refresh_secs: u64,
    /// Sources within one symbol may differ by at most this fraction.
    pub max_spread: f64,
    /// A single-source reading may not jump more than this from the last
    /// accepted one; two agreeing sources may.
    pub max_jump: f64,
}

impl Default for FeedConfig {
    fn default() -> Self {
        FeedConfig { interval_secs: 60, move_bps: 10, refresh_secs: 600, max_spread: 0.05, max_jump: 0.20 }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FeedHealth {
    pub last_ok: Option<u64>,
    pub failures: u32,
    pub last_error: Option<String>,
    pub posted: u64,
    /// Symbols priced in the last cycle.
    pub priced: Vec<String>,
}

pub struct Feeds<F: Fetcher> {
    pub cfg: FeedConfig,
    pub map: BTreeMap<String, Vec<Source>>,
    pub fetcher: F,
    /// Last accepted USD price per symbol.
    pub last: BTreeMap<String, f64>,
    /// Last posted reference per pool, and when.
    pub posted: BTreeMap<PoolId, (f64, u64)>,
    /// The same for assets that have no pool yet.
    pub posted_assets: BTreeMap<swapvm::types::AssetId, (f64, u64)>,
}

impl<F: Fetcher> Feeds<F> {
    pub fn new(cfg: FeedConfig, map: BTreeMap<String, Vec<Source>>, fetcher: F) -> Feeds<F> {
        Feeds { cfg, map, fetcher, last: BTreeMap::new(), posted: BTreeMap::new(), posted_assets: BTreeMap::new() }
    }

    /// USD prices for the symbols, from every source that answers. A symbol
    /// with no agreeing sources, or a lone source that jumped, is left out.
    pub fn prices(&mut self, symbols: &[String]) -> (BTreeMap<String, f64>, Vec<String>) {
        let mut out = BTreeMap::new();
        let mut errors = Vec::new();
        let ids: Vec<String> = symbols.iter().filter_map(|s| self.map.get(s)).flatten().filter_map(|s| match s { Source::CoinGecko(id) => Some(id.clone()), _ => None }).collect();
        self.fetcher.prime(&ids);
        for sym in symbols {
            let Some(sources) = self.map.get(sym) else { continue };
            let mut samples = Vec::new();
            for s in sources {
                match self.fetcher.fetch(s) {
                    Ok(x) => samples.push(x),
                    Err(e) => errors.push(format!("{} {}: {}", sym, s.name(), e)),
                }
            }
            let n = samples.len();
            let Some(px) = aggregate(samples, self.cfg.max_spread) else {
                if n > 0 { errors.push(format!("{}: sources disagree", sym)) }
                continue;
            };
            if n == 1 {
                if let Some(prev) = self.last.get(sym) {
                    if ((px - prev) / prev).abs() > self.cfg.max_jump {
                        errors.push(format!("{}: single source jumped {:.1}%, ignored", sym, 100.0 * (px - prev) / prev));
                        continue;
                    }
                }
            }
            self.last.insert(sym.clone(), px);
            out.insert(sym.clone(), px);
        }
        (out, errors)
    }

    /// `asset1 per asset0` for each pool whose two assets both priced.
    pub fn references(&self, pools: &[(PoolId, Side, Side)], prices: &BTreeMap<String, f64>) -> Vec<(PoolId, f64)> {
        pools.iter().filter_map(|(id, s0, s1)| {
            let b0 = base_symbol_from(&s0.0, s0.1, &self.map)?;
            let b1 = base_symbol_from(&s1.0, s1.1, &self.map)?;
            let (p0, p1) = (*prices.get(&b0)?, *prices.get(&b1)?);
            (p1 > 0.0).then_some((*id, p0 / p1))
        }).collect()
    }

    /// Units of the asset per ZEC.zy, for each asset that has no pool.
    pub fn asset_references(&self, pending: &[(swapvm::types::AssetId, Side)], prices: &BTreeMap<String, f64>) -> Vec<(swapvm::types::AssetId, f64)> {
        let zec = match prices.get("ZEC") { Some(z) if *z > 0.0 => *z, _ => return Vec::new() };
        pending.iter().filter_map(|(id, side)| {
            let b = base_symbol_from(&side.0, side.1, &self.map)?;
            let p = *prices.get(&b)?;
            (p > 0.0).then_some((*id, zec / p))
        }).collect()
    }

    /// Whether a reference is worth posting: moved enough, or old enough.
    pub fn due(&self, pool: PoolId, price: f64, now: u64) -> bool {
        match self.posted.get(&pool) {
            None => true,
            Some((last, at)) => {
                let moved = ((price - last) / last).abs() * 10_000.0 > self.cfg.move_bps as f64;
                moved || now.saturating_sub(*at) >= self.cfg.refresh_secs
            }
        }
    }
}

/// A pool side: the asset's symbol and the chain it was bridged from (0 if native).
pub type Side = (String, u16);

/// Bridged assets with no market against ZEC.zy yet: the ones whose price
/// the chain needs in order to open one (`Intent::UpdateAssetReference`).
pub fn pending_assets(state: &SwapState) -> Vec<(swapvm::types::AssetId, Side)> {
    state.tokens.iter().filter_map(|(id, t)| {
        let v = t.vault?;
        if *id == swapvm::types::XZEC || !t.is_divisible() || state.find_pool(swapvm::types::XZEC, *id).is_some() {
            return None;
        }
        Some((*id, (String::from_utf8_lossy(&t.symbol).trim_end_matches('\0').to_string(), v.origin)))
    }).collect()
}

/// The pools with both sides named, from the chain.
pub fn pool_pairs(state: &SwapState) -> Vec<(PoolId, Side, Side)> {
    let side = |a: u32| -> Side {
        state.tokens.get(&a).map(|t| (String::from_utf8_lossy(&t.symbol).trim_end_matches('\0').to_string(), t.vault.map(|v| v.origin).unwrap_or(0))).unwrap_or_default()
    };
    state.pools.iter().map(|(id, p)| (*id, side(p.asset0), side(p.asset1))).collect()
}

/// One cycle: price what the pools need and post what moved. Returns the
/// number of references posted.
pub fn cycle<F: Fetcher>(feeds: &mut Feeds<F>, shared: &Arc<Mutex<Node<SwapState>>>, now: u64, health: &Arc<Mutex<FeedHealth>>) -> Result<u64, String> {
    let (pairs, pending) = { let n = shared.lock().map_err(|_| "node lock poisoned")?; (pool_pairs(n.state()), pending_assets(n.state())) };
    let mut symbols: Vec<String> = pairs.iter().flat_map(|(_, a, b)| [a, b]).filter_map(|s| base_symbol_from(&s.0, s.1, &feeds.map)).collect();
    symbols.extend(pending.iter().filter_map(|(_, s)| base_symbol_from(&s.0, s.1, &feeds.map)));
    if !pending.is_empty() { symbols.push("ZEC".to_string()); }
    symbols.sort();
    symbols.dedup();
    let (prices, errors) = feeds.prices(&symbols);
    for e in &errors { eprintln!("zynzapd: feed: {}", e); }
    let refs = feeds.references(&pairs, &prices);
    let mut posted = 0;
    for (pool, price) in refs {
        if !feeds.due(pool, price, now) { continue }
        let Some(fx) = to_fixed(price) else { continue };
        let mut n = shared.lock().map_err(|_| "node lock poisoned")?;
        let step = n.submit_operator(Intent::UpdateReference { pool, price: fx }, now);
        if step.rejected() {
            eprintln!("zynzapd: feed: reference for pool {} refused: {:?}", pool, step.receipts);
            continue;
        }
        let fee = step.receipts.iter().find_map(|r| match r { swapvm::tx::Receipt::ReferenceUpdated { fee_bps, .. } => Some(*fee_bps), _ => None }).unwrap_or(0);
        eprintln!("zynzapd: feed: pool {} reference {} (fee now {} bps)", pool, fx, fee);
        feeds.posted.insert(pool, (price, now));
        posted += 1;
    }
    // Assets with no market yet: the chain needs a price to open one at.
    for (asset, price) in feeds.asset_references(&pending, &prices) {
        let last = feeds.posted_assets.get(&asset).copied();
        let due = match last { None => true, Some((p, at)) => ((price - p) / p).abs() * 10_000.0 > feeds.cfg.move_bps as f64 || now.saturating_sub(at) >= feeds.cfg.refresh_secs };
        if !due { continue }
        let Some(fx) = to_fixed(price) else { continue };
        let mut n = shared.lock().map_err(|_| "node lock poisoned")?;
        let step = n.submit_operator(Intent::UpdateAssetReference { asset, price: fx }, now);
        if step.rejected() {
            eprintln!("zynzapd: feed: price for asset {} refused: {:?}", asset, step.receipts);
            continue;
        }
        eprintln!("zynzapd: feed: asset {} priced at {} per ZEC.zy (no market yet)", asset, fx);
        feeds.posted_assets.insert(asset, (price, now));
        posted += 1;
    }
    if let Ok(mut h) = health.lock() {
        h.priced = prices.keys().cloned().collect();
        if prices.is_empty() && !symbols.is_empty() {
            h.failures = h.failures.saturating_add(1);
            h.last_error = errors.last().cloned();
        } else {
            h.last_ok = Some(now);
            h.failures = 0;
            h.last_error = None;
            h.posted += posted;
        }
    }
    if prices.is_empty() && !symbols.is_empty() {
        return Err(errors.last().cloned().unwrap_or_else(|| "no source answered".into()));
    }
    Ok(posted)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(BTreeMap<String, Result<f64, String>>);
    impl Fetcher for Fake {
        fn fetch(&self, source: &Source) -> Result<f64, String> {
            let key = match source {
                Source::Coinbase(s) | Source::CoinGecko(s) | Source::Nasdaq(s) | Source::Yahoo(s) | Source::Frankfurter(s) => format!("{}:{}", source.name(), s),
                Source::Constant(x) => return Ok(*x),
                Source::Chainlink(_, feed, _) => format!("chainlink:{}", feed),
                Source::Scaled(_, token, inner) => { let base = self.fetch(inner)?; return Ok(base * self.0.get(&format!("mult:{}", token)).cloned().unwrap_or(Ok(1.0))?) }
            };
            self.0.get(&key).cloned().unwrap_or_else(|| Err("unknown".into()))
        }
    }

    #[test]
    fn zyn_symbols_map_to_market_symbols() {
        let m = default_map();
        assert_eq!(base_symbol("SOL.zy", &m).as_deref(), Some("SOL"));
        assert_eq!(base_symbol("ZEC.zy", &m).as_deref(), Some("ZEC"));
        assert_eq!(base_symbol("TSLAx.zy", &m).as_deref(), Some("X:TSLA"), "an xStocks token is the token");
        assert_eq!(base_symbol("bAAPL.zy", &m).as_deref(), Some("AAPL"), "an unknown decoration falls back to the share");
        assert_eq!(base_symbol("wBTC.zy", &m).as_deref(), Some("BTC"));
        assert_eq!(base_symbol("USDC.zy", &m).as_deref(), Some("USDC"));
        assert_eq!(base_symbol("ART", &m), None, "a token launched here has no market");
        assert_eq!(base_symbol("LP-1", &m), None);
    }

    #[test]
    fn the_median_is_taken_and_disagreement_refuses() {
        assert_eq!(aggregate(vec![100.0, 101.0, 99.0], 0.05), Some(100.0));
        assert_eq!(aggregate(vec![100.0, 102.0], 0.05), Some(101.0));
        assert_eq!(aggregate(vec![100.0, 120.0], 0.05), None, "20% apart is not a price");
        assert_eq!(aggregate(vec![f64::NAN, 50.0], 0.05), Some(50.0));
        assert_eq!(aggregate(vec![], 0.05), None);
    }

    #[test]
    fn parsers_read_each_source() {
        assert_eq!(parse_coinbase(r#"{"data":{"base":"BTC","currency":"USD","amount":"63000.12"}}"#).unwrap(), 63000.12);
        assert_eq!(parse_coingecko(r#"{"zcash":{"usd":41.7}}"#, "zcash").unwrap(), 41.7);
        assert_eq!(parse_nasdaq(r#"{"data":{"symbol":"AAPL","primaryData":{"lastSalePrice":"$1,319.97","netChange":"-8.24"}}}"#).unwrap(), 1319.97);
        assert!(parse_nasdaq(r#"{"data":null,"message":null,"status":{"rCode":400}}"#).is_err());
        assert_eq!(parse_yahoo(r#"{"chart":{"result":[{"meta":{"regularMarketPrice":412.5}}],"error":null}}"#).unwrap(), 412.5);
        assert_eq!(parse_frankfurter(r#"{"amount":1.0,"base":"EUR","rates":{"USD":1.0842}}"#).unwrap(), 1.0842);
    }

    #[test]
    fn a_pool_reference_is_asset1_per_asset0() {
        let mut fake = BTreeMap::new();
        fake.insert("coinbase:ZEC".into(), Ok(40.0));
        fake.insert("coingecko:zcash".into(), Ok(41.0));
        fake.insert("coinbase:SOL".into(), Ok(200.0));
        fake.insert("coingecko:solana".into(), Ok(202.0));
        let mut f = Feeds::new(FeedConfig::default(), default_map(), Fake(fake));
        let (prices, errors) = f.prices(&["ZEC".into(), "SOL".into()]);
        assert!(errors.is_empty(), "{:?}", errors);
        assert_eq!(prices["ZEC"], 40.5);
        assert_eq!(prices["SOL"], 201.0);
        // Pool 1 is ZEC.zy : SOL.zy → SOL per ZEC ≈ 0.2015.
        let refs = f.references(&[(1, ("ZEC.zy".into(), 0), ("SOL.zy".into(), 0)), (2, ("ART".into(), 0), ("ZEC.zy".into(), 0))], &prices);
        assert_eq!(refs.len(), 1, "a pool with an unpriceable side gets no reference");
        assert!((refs[0].1 - 40.5 / 201.0).abs() < 1e-12);
        assert_eq!(to_fixed(0.2).unwrap(), Fixed::raw(200_000_000_000_000_000));
    }

    #[test]
    fn a_lone_source_may_not_jump_and_posting_is_by_move_or_age() {
        let mut fake = BTreeMap::new();
        fake.insert("coingecko:ousg".into(), Ok(100.0));
        let mut f = Feeds::new(FeedConfig::default(), default_map(), Fake(fake));
        let (p, _) = f.prices(&["OUSG".into()]);
        assert_eq!(p["OUSG"], 100.0);
        f.fetcher.0.insert("coingecko:ousg".into(), Ok(140.0));
        let (p, errors) = f.prices(&["OUSG".into()]);
        assert!(!p.contains_key("OUSG"), "a 40% jump from one source is not believed");
        assert!(errors[0].contains("jumped"));

        assert!(f.due(1, 0.2, 1_000));
        f.posted.insert(1, (0.2, 1_000));
        assert!(!f.due(1, 0.20001, 1_010), "a hair of movement is not worth a post");
        assert!(f.due(1, 0.2003, 1_010), "15 bps is");
        assert!(f.due(1, 0.2, 1_000 + 600), "and so is age");
    }

    #[test]
    fn robinhood_tokens_are_priced_as_tokens_not_shares() {
        let m = default_map();
        let toks = robinhood_tokens();
        assert!(toks.len() > 150, "{} tokens", toks.len());
        assert_eq!(toks["AAPL"].0, "0xaF3D76f1834A1d425780943C99Ea8A608f8a93f9");
        let feeds = robinhood_feeds();
        assert_eq!(feeds["AAPL"].0, "0x6B22A786bAa607d76728168703a39Ea9C99f2cD0");
        assert!(m["RH:AAPL"].len() >= 3, "feed + scaled share sources");
        assert!(m["RH:AAOI"].len() >= 2, "no feed; token price and scaled share sources");
        assert_eq!(base_symbol_from("AAPL.zy", zyn_bridge::evm::ORIGIN_ROBINHOOD_CHAIN, &m).as_deref(), Some("RH:AAPL"));
        assert_eq!(base_symbol_from("AAPL.zy", 0, &m).as_deref(), Some("AAPL"), "the bare share otherwise");
        assert_eq!(base_symbol_from("SOL.zy", zyn_bridge::evm::ORIGIN_ROBINHOOD_CHAIN, &m).as_deref(), Some("SOL"), "not a stock: falls through");
    }

    #[test]
    fn issuer_decorations_name_the_token() {
        let m = default_map();
        let t = tokenized_stocks();
        assert!(t.len() > 1500, "{} tokenised stocks", t.len());
        assert_eq!(t[&("X".to_string(), "TSLA".to_string())], "tesla-xstock");
        assert_eq!(base_symbol_from("TSLAx.zy", 0, &m).as_deref(), Some("X:TSLA"));
        assert_eq!(base_symbol_from("AAPLon.zy", 0, &m).as_deref(), Some("ON:AAPL"));
        assert_eq!(base_symbol_from("AAPL.d.zy", 0, &m).as_deref(), Some("D:AAPL"));
        assert_eq!(base_symbol_from("NVDA.zy", 0, &m).as_deref(), Some("NVDA"), "undecorated is the share");
        assert_eq!(m["X:TSLA"].len(), 3);
        assert!(matches!(m["X:TSLA"][0], Source::CoinGecko(_)));
        assert!(matches!(m["RH:AAPL"][0], Source::Chainlink(..)));
        assert_eq!(m["RH:AAPL"].len(), 4, "feed, coingecko, and two scaled share sources");
    }

    #[test]
    fn a_chainlink_round_decodes() {
        let hex = "000000000000000000000000000000000000000000000001000000000000023800000000000000000000000000000000000000000000000000000007766d1d75000000000000000000000000000000000000000000000000000000006a9b2132000000000000000000000000000000000000000000000000000000006a9b213e0000000000000000000000000000000000000000000000010000000000000238";
        let ret: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
        let (answer, updated) = decode_round(&ret).unwrap();
        assert_eq!(answer, 32_051_633_525, "AAPL at 8 decimals: $320.52");
        assert_eq!(updated, 1_788_551_486);
        let post = |_: &str, _: &str| -> Result<String, String> { Ok(format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{}"}}"#, hex)) };
        let r = eth_call(&post, "rpc", "0xfeed", "0xfeaf968c").unwrap();
        assert_eq!(r.len(), 160);
        let bad = |_: &str, _: &str| -> Result<String, String> { Ok(r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted"}}"#.into()) };
        assert!(eth_call(&bad, "rpc", "0xfeed", "0xfeaf968c").is_err());
    }

    #[test]
    fn overrides_replace_a_symbol() {
        let mut m = default_map();
        apply_overrides(&mut m, "TSLA=yahoo:TSLA, GOLD=coingecko:pax-gold|coinbase:PAXG").unwrap();
        assert_eq!(m["TSLA"], vec![Source::Yahoo("TSLA".into())]);
        assert_eq!(m["GOLD"].len(), 2);
        assert!(apply_overrides(&mut m, "BAD").is_err());
        assert!(apply_overrides(&mut m, "X=nowhere:1").is_err());
    }
}
