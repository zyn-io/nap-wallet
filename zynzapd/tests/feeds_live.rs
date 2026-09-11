//! Every source, once, against the real internet. Ignored by default; run
//! with `cargo test -p zynzapd --test feeds_live -- --ignored --nocapture`.
use zynzapd::feeds::{Fetcher, Http, Source};

#[test]
#[ignore]
fn every_source_answers() {
    let h = Http::default();
    let probes = [
        Source::Coinbase("ZEC".into()), Source::Coinbase("SOL".into()), Source::Coinbase("USDT".into()),
        Source::CoinGecko("zcash".into()), Source::CoinGecko("ondo-us-dollar-yield".into()), Source::CoinGecko("ousg".into()),
        Source::CoinGecko("blackrock-usd-institutional-digital-liquidity-fund".into()), Source::CoinGecko("pax-gold".into()),
        Source::Nasdaq("AAPL".into()), Source::Nasdaq("SPY".into()), Source::Yahoo("TSLA".into()), Source::Frankfurter("EUR".into()),
        Source::Chainlink(zynzapd::feeds::ROBINHOOD_RPC.into(), "0x6B22A786bAa607d76728168703a39Ea9C99f2cD0".into(), 86_400),
        Source::Scaled(zynzapd::feeds::ROBINHOOD_RPC.into(), "0xaF3D76f1834A1d425780943C99Ea8A608f8a93f9".into(), Box::new(Source::Nasdaq("AAPL".into()))),
    ];
    let mut failed = Vec::new();
    for p in &probes {
        match h.fetch(p) {
            Ok(x) => println!("{:<12} {:<50} {}", p.name(), format!("{:?}", p), x),
            Err(e) => { println!("{:<12} {:<50} FAILED: {}", p.name(), format!("{:?}", p), e); failed.push(format!("{:?}", p)); }
        }
    }
    assert!(failed.len() <= 3, "too many sources failed: {:?}", failed);
}

#[test]
#[ignore]
fn tokenised_stocks_price_by_issuer() {
    use zynzapd::feeds::{default_map, FeedConfig, Feeds};
    let mut f = Feeds::new(FeedConfig::default(), default_map(), Http::default());
    let syms: Vec<String> = ["X:TSLA", "ON:AAPL", "RH:AAPL", "D:AAPL", "AAPL", "TSLA"].iter().map(|s| s.to_string()).collect();
    let (prices, errors) = f.prices(&syms);
    for (k, v) in &prices { println!("{:<10} {}", k, v); }
    for e in &errors { println!("err: {}", e); }
    assert!(prices.len() >= 4, "{:?}", prices);
}
