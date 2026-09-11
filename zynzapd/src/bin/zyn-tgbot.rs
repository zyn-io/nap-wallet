//! A pager you can also ask questions.
//!
//! The alerts already exist and already work — `alert.rs` detected the halt on
//! 9 Sep, announced it, and announced the recovery. What it lacked was anywhere
//! to send them: `ZYN_ALERT_URL` was unset, so a stuck chain sat in journald
//! for a day and a half. Point that variable at Telegram's `sendMessage` and
//! the push half is solved with no code, because the webhook body already
//! carries a `text` field and Telegram takes `chat_id` from the query string.
//!
//! This binary is the other half: the ability to *ask*. Alerts tell you when
//! something broke; they cannot tell you the state of a thing that is merely
//! slow, or answer "is it back yet" without waiting for the next poll.
//!
//! It runs beside the sequencer and reads only what the RPC already exposes.
//! It holds no key, signs nothing, and submits nothing — every op it calls is
//! a public read, so the worst a compromised bot token can do is tell someone
//! the chain's height, which the DA store publishes anyway.

use std::time::Duration;

use zynzapd::client::Node;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

struct Bot {
    token: String,
    /// Chats allowed to talk to it. Empty means answer nobody — a bot that
    /// answers anyone is a bot whose token is a disclosure.
    allowed: Vec<i64>,
    agent: ureq::Agent,
    node: Node,
    /// `(label, host:port)` for each Zcash node worth watching.
    zebras: Vec<(String, String)>,
}

impl Bot {
    fn api(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.token, method)
    }

    fn call(&self, method: &str, body: serde_json::Value) -> Option<serde_json::Value> {
        match self.agent.post(&self.api(method)).send_json(body) {
            Ok(r) => r.into_json::<serde_json::Value>().ok(),
            Err(e) => {
                eprintln!("zyn-tgbot: {} failed: {}", method, e);
                None
            }
        }
    }

    fn keyboard() -> serde_json::Value {
        serde_json::json!({
            "inline_keyboard": [
                [{"text": "chain", "callback_data": "/status"},
                 {"text": "signers", "callback_data": "/signers"}],
                [{"text": "anchors", "callback_data": "/anchors"},
                 {"text": "offers", "callback_data": "/offers"}],
                [{"text": "zcash nodes", "callback_data": "/nodes"}],
            ]
        })
    }

    fn say(&self, chat: i64, text: &str) {
        self.call("sendMessage", serde_json::json!({
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": Self::keyboard(),
        }));
    }

    /// Height, epoch, and — the number that mattered on 9 Sep — how far the
    /// last anchor is behind the tip. A sequencer waiting on signatures looks
    /// healthy in every other respect.
    fn status(&self) -> String {
        let s = match self.node.status() {
            Ok(s) => s,
            Err(e) => return format!("chain {}: unreachable — {}", self.node.chain, e),
        };
        let lag = s.epoch.saturating_sub(s.anchored_epoch);
        let mark = if lag > 60 { "\u{26a0}" } else { "\u{2713}" };
        let mut out = format!(
            "<b>chain {}</b>\nepoch <b>{}</b>  seq {}\nlast anchor <b>{}</b>  (lag {} {})\nbacking {}  pools {}  accounts {}",
            self.node.chain, s.epoch, s.seq, s.anchored_epoch, lag, mark, s.backing, s.pools, s.accounts
        );
        if s.forced_pending > 0 || s.censored > 0 {
            out.push_str(&format!("\nforced pending {}  censored {}", s.forced_pending, s.censored));
        }
        let down: Vec<&str> = s.health.iter().filter(|h| h.down).map(|h| h.name.as_str()).collect();
        out.push_str(&if down.is_empty() {
            format!("\n\u{2713} {} source(s) healthy", s.health.len())
        } else {
            format!("\n\u{26a0} DOWN: {}", down.join(", "))
        });
        out
    }

    /// Per-source health as the sequencer sees it, with how stale each is.
    fn signers(&self) -> String {
        let s = match self.node.status() {
            Ok(s) => s,
            Err(e) => return format!("unreachable — {}", e),
        };
        if s.health.is_empty() {
            return "no health sources reported".into();
        }
        let mut out = String::from("<b>sources</b>\n");
        for h in &s.health {
            let mark = if h.down { "\u{26a0}" } else { "\u{2713}" };
            out.push_str(&format!("{} <b>{}</b> — scanned to {}", mark, h.name, h.scanned_to));
            if !h.error.is_empty() {
                let msg: String = h.error.chars().take(90).collect();
                out.push_str(&format!("\n    {}", msg));
            }
            out.push('\n');
        }
        out
    }

    /// The epoch-to-Zcash mapping, newest last. This is the thing worth being
    /// able to check from a phone: whether roots are still reaching Zcash.
    fn anchors(&self) -> String {
        match self.node.anchors(5) {
            Err(e) => format!("anchors unavailable — {}", e),
            Ok(a) if a.is_empty() => "no anchors published yet".into(),
            Ok(a) => {
                let mut out = String::from("<b>recent anchors</b>\n");
                for x in &a {
                    out.push_str(&format!(
                        "epoch <b>{}</b> @ height {}\n  <code>{}</code>\n",
                        x.epoch, x.height, x.txid
                    ));
                }
                out
            }
        }
    }

    /// Both Zcash nodes: height against the network's own estimate of the tip.
    ///
    /// A node that is merely *behind* looks identical to one that is healthy if
    /// you only read its height, so the gap is the number reported. Zebra's
    /// `estimatedheight` is the network's view, so `lag` is honest even when
    /// the node is the thing that is wrong.
    fn nodes(&self) -> String {
        let mut out = String::from("<b>zcash nodes</b>\n");
        for (label, addr) in &self.zebras {
            let url = format!("http://{}/", addr);
            let body = serde_json::json!({
                "jsonrpc": "1.0", "id": 1, "method": "getblockchaininfo", "params": []
            });
            match self.agent.post(&url).timeout(Duration::from_secs(8)).send_json(body) {
                Err(e) => {
                    let msg = e.to_string();
                    out.push_str(&format!("\u{26a0} <b>{}</b> unreachable\n    {}\n", label, msg.chars().take(70).collect::<String>()));
                }
                Ok(r) => {
                    let v: serde_json::Value = r.into_json().unwrap_or(serde_json::Value::Null);
                    let res = v.get("result").unwrap_or(&serde_json::Value::Null);
                    let blocks = res.get("blocks").and_then(|x| x.as_u64()).unwrap_or(0);
                    let tip = res.get("estimatedheight").and_then(|x| x.as_u64()).unwrap_or(0);
                    let chain = res.get("chain").and_then(|x| x.as_str()).unwrap_or("?");
                    let lag = tip.saturating_sub(blocks);
                    // Two blocks of slack: mainnet produces one every ~75s, so
                    // a node exactly at tip still reads one behind much of the time.
                    let mark = if lag <= 2 { "\u{2713}" } else { "\u{26a0}" };
                    out.push_str(&format!(
                        "{} <b>{}</b> ({})  height <b>{}</b>\n    tip {}  lag {}\n",
                        mark, label, chain, blocks, tip, lag
                    ));
                }
            }
        }
        out
    }

    fn offers(&self) -> String {
        match self.node.offers() {
            Err(e) => format!("offers unavailable — {}", e),
            Ok(o) if o.is_empty() => "no resting offers".into(),
            Ok(o) => {
                let mut out = format!("<b>{} resting offer(s)</b>\n", o.len());
                for x in o.iter().take(10) {
                    out.push_str(&format!(
                        "#{} asset {} \u{2192} {} of asset {}\n",
                        x.id, x.offer_asset, x.want_amount, x.want_asset
                    ));
                }
                out
            }
        }
    }

    fn answer(&self, cmd: &str) -> String {
        match cmd.split_whitespace().next().unwrap_or("").trim_start_matches('/') {
            "status" | "start" => self.status(),
            "signers" | "health" => self.signers(),
            "anchors" => self.anchors(),
            "offers" => self.offers(),
            "nodes" | "zebra" => self.nodes(),
            "help" => "/status  chain height, last anchor, lag\n/signers  per-source health\n/anchors  recent roots on Zcash\n/offers  the order book\n/nodes  zcash mainnet + testnet sync".into(),
            other => format!("unknown command: {}\ntry /help", other),
        }
    }

    fn run(&self) {
        let mut offset: i64 = 0;
        eprintln!("zyn-tgbot: polling; answering {} chat(s); node {}", self.allowed.len(), self.node.addr);
        loop {
            let body = serde_json::json!({ "timeout": 50, "offset": offset });
            let Some(v) = self.call("getUpdates", body) else {
                std::thread::sleep(Duration::from_secs(5));
                continue;
            };
            let Some(items) = v.get("result").and_then(|r| r.as_array()) else { continue };
            for u in items {
                if let Some(id) = u.get("update_id").and_then(|x| x.as_i64()) {
                    offset = id + 1;
                }
                // A button press and a typed command are the same question;
                // only where the text comes from differs.
                let (chat, text, callback) = if let Some(cb) = u.get("callback_query") {
                    (
                        cb.pointer("/message/chat/id").and_then(|x| x.as_i64()),
                        cb.get("data").and_then(|x| x.as_str()).map(str::to_string),
                        cb.get("id").and_then(|x| x.as_str()).map(str::to_string),
                    )
                } else {
                    (
                        u.pointer("/message/chat/id").and_then(|x| x.as_i64()),
                        u.pointer("/message/text").and_then(|x| x.as_str()).map(str::to_string),
                        None,
                    )
                };
                if let Some(cb) = callback {
                    self.call("answerCallbackQuery", serde_json::json!({ "callback_query_id": cb }));
                }
                let (Some(chat), Some(text)) = (chat, text) else { continue };
                if !self.allowed.contains(&chat) {
                    eprintln!("zyn-tgbot: ignoring chat {}", chat);
                    continue;
                }
                let reply = self.answer(&text);
                self.say(chat, &reply);
            }
        }
    }
}

fn main() -> Result<(), String> {
    let token = env("ZYN_TG_TOKEN").ok_or("ZYN_TG_TOKEN is required")?;
    let allowed: Vec<i64> = env("ZYN_TG_CHATS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if allowed.is_empty() {
        return Err("ZYN_TG_CHATS is required: a comma-separated list of chat ids allowed to ask".into());
    }
    let addr = env("ZYN_NODE").unwrap_or_else(|| "127.0.0.1:8099".into());
    // Two Zcash nodes, and neither is optional to the story: testnet is what
    // chain 11 anchors into, mainnet is what the vault will custody against.
    let zebras: Vec<(String, String)> = vec![
        ("testnet".into(), env("ZYN_ZEBRA_TESTNET").unwrap_or_else(|| "127.0.0.1:18232".into())),
        ("mainnet".into(), env("ZYN_ZEBRA_MAINNET").unwrap_or_else(|| "127.0.0.1:8232".into())),
    ];
    let chain: u32 = env("ZYN_CHAIN_ID").unwrap_or_else(|| "11".into()).parse().map_err(|_| "ZYN_CHAIN_ID")?;

    let bot = Bot {
        token,
        allowed,
        agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(60)).build(),
        node: Node::new(&addr, chain),
        zebras,
    };
    bot.run();
    Ok(())
}
