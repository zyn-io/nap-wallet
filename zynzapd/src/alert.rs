//! Saying so when something has stopped.
//!
//! Every failure in the bridges is logged, and nobody reads the journal. A
//! memo-less deposit halts the deposit scan *by design* — the money is real
//! and guessing its owner is the one thing not to do — and that design is
//! only safe if a human learns about it. This is how they learn.
//!
//! Components report after every pass. The alerter reacts to **transitions**,
//! not to noise: a component that has failed [`Alerter::after_failures`]
//! passes in a row, or has had no successful pass for [`Alerter::stall_secs`],
//! is *down*; the first pass that succeeds afterwards is *recovered*. Each
//! transition is one line in the journal with a fixed prefix, and one POST to
//! the webhook if there is one; a component that stays down is re-announced
//! hourly, so a missed message is not a missed outage.
//!
//! The webhook body is `{"text": …}` plus fields — the shape Slack, Discord
//! (`/slack` endpoints) and most pagers accept without configuration.

use std::collections::BTreeMap;
use std::time::Duration;

/// One component's state, as last reported.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Health {
    pub name: String,
    pub scanned_to: u64,
    pub last_ok: Option<u64>,
    pub failures: u32,
    pub last_error: Option<String>,
    pub down: bool,
}

/// Where an alert goes. Real deployments post to a URL; tests capture.
pub trait Sink {
    fn send(&mut self, text: &str, fields: &BTreeMap<&'static str, String>);
}

/// `POST` a JSON body to a webhook. Failures to deliver are logged and not
/// retried: the journal line already went out, and an alerter that blocks
/// the poll loop on a dead pager is worse than a missed page.
pub struct Webhook {
    pub url: String,
    agent: ureq::Agent,
}

impl Webhook {
    pub fn new(url: &str) -> Webhook {
        Webhook { url: url.to_string(), agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(10)).build() }
    }
}

impl Sink for Webhook {
    fn send(&mut self, text: &str, fields: &BTreeMap<&'static str, String>) {
        let mut body = serde_json::json!({ "text": text, "content": text });
        for (k, v) in fields {
            body[*k] = serde_json::Value::String(v.clone());
        }
        if let Err(e) = self.agent.post(&self.url).send_json(body) {
            eprintln!("zynzapd: ALERT delivery to webhook failed: {}", e);
        }
    }
}

pub struct Alerter<S: Sink> {
    sink: Option<S>,
    chain_id: u32,
    pub after_failures: u32,
    pub stall_secs: u64,
    /// Re-announce a component still down after this long.
    pub remind_secs: u64,
    states: BTreeMap<String, Health>,
    announced: BTreeMap<String, u64>,
}

impl<S: Sink> Alerter<S> {
    pub fn new(sink: Option<S>, chain_id: u32) -> Alerter<S> {
        Alerter { sink, chain_id, after_failures: 3, stall_secs: 900, remind_secs: 3600, states: BTreeMap::new(), announced: BTreeMap::new() }
    }

    /// Record one pass of `name`. `Ok(scanned_to)` or the error it ended in.
    pub fn report(&mut self, name: &str, now: u64, result: Result<u64, String>) {
        let h = self.states.entry(name.to_string()).or_insert_with(|| Health {
            name: name.to_string(), scanned_to: 0, last_ok: None, failures: 0, last_error: None, down: false,
        });
        match result {
            Ok(to) => {
                h.scanned_to = to;
                h.last_ok = Some(now);
                h.failures = 0;
                h.last_error = None;
            }
            Err(e) => {
                h.failures = h.failures.saturating_add(1);
                h.last_error = Some(e);
            }
        }
        let stalled = h.last_ok.map(|t| now.saturating_sub(t) >= self.stall_secs).unwrap_or(false);
        let failing = h.failures >= self.after_failures;
        let should_be_down = failing || stalled;
        let snapshot = h.clone();
        match (snapshot.down, should_be_down) {
            (false, true) => {
                self.states.get_mut(name).unwrap().down = true;
                self.announced.insert(name.to_string(), now);
                self.emit("DOWN", &snapshot, now);
            }
            (true, false) => {
                self.states.get_mut(name).unwrap().down = false;
                self.announced.remove(name);
                self.emit("RECOVERED", &snapshot, now);
            }
            (true, true) => {
                let last = self.announced.get(name).copied().unwrap_or(0);
                if now.saturating_sub(last) >= self.remind_secs {
                    self.announced.insert(name.to_string(), now);
                    self.emit("STILL DOWN", &snapshot, now);
                }
            }
            (false, false) => {}
        }
    }

    fn emit(&mut self, what: &str, h: &Health, now: u64) {
        let detail = h.last_error.clone().unwrap_or_else(|| "no successful pass".to_string());
        let text = format!(
            "zyn chain {} — {} {}: {} (scanned to {}, {} consecutive failure(s), last ok {})",
            self.chain_id, h.name, what, detail, h.scanned_to, h.failures,
            h.last_ok.map(|t| format!("{}s ago", now.saturating_sub(t))).unwrap_or_else(|| "never".into())
        );
        eprintln!("zynzapd: ALERT {}", text);
        if let Some(s) = self.sink.as_mut() {
            let mut fields = BTreeMap::new();
            fields.insert("component", h.name.clone());
            fields.insert("state", what.to_string());
            fields.insert("detail", detail);
            fields.insert("chain", self.chain_id.to_string());
            s.send(&text, &fields);
        }
    }

    pub fn health(&self) -> Vec<Health> {
        self.states.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Captured(Vec<String>);
    impl Sink for Captured {
        fn send(&mut self, text: &str, _: &BTreeMap<&'static str, String>) {
            self.0.push(text.to_string());
        }
    }

    fn alerter() -> Alerter<Captured> {
        let mut a = Alerter::new(Some(Captured::default()), 11);
        a.after_failures = 3;
        a.stall_secs = 100;
        a.remind_secs = 1000;
        a
    }
    fn sent(a: &Alerter<Captured>) -> Vec<String> {
        a.sink.as_ref().unwrap().0.clone()
    }

    /// One bad pass is weather. Three in a row is an outage — announced
    /// once, and again when it clears.
    #[test]
    fn failures_alert_on_the_transition_not_on_every_pass() {
        let mut a = alerter();
        a.report("zcash", 10, Ok(100));
        a.report("zcash", 20, Err("memo".into()));
        a.report("zcash", 30, Err("memo".into()));
        assert!(sent(&a).is_empty(), "two failures are not an outage yet");
        a.report("zcash", 40, Err("memo".into()));
        assert_eq!(sent(&a).len(), 1);
        assert!(sent(&a)[0].contains("DOWN") && sent(&a)[0].contains("memo"));
        a.report("zcash", 50, Err("memo".into()));
        assert_eq!(sent(&a).len(), 1, "a component still down is not re-announced every pass");
        a.report("zcash", 60, Ok(101));
        assert_eq!(sent(&a).len(), 2);
        assert!(sent(&a)[1].contains("RECOVERED"));
    }

    /// Quiet is not fine: no successful pass for the stall window is an
    /// outage even if every pass "succeeded" at doing nothing… which cannot
    /// happen here, but a component that only ever errors under the
    /// threshold can. The clock catches what the counter does not.
    #[test]
    fn a_stall_alerts_even_below_the_failure_threshold() {
        let mut a = alerter();
        a.report("solana", 0, Ok(5));
        a.report("solana", 50, Err("429".into()));
        a.report("solana", 99, Ok(6)); // recovers the clock
        a.report("solana", 150, Err("429".into()));
        assert!(sent(&a).is_empty());
        a.report("solana", 200, Err("429".into()));
        assert_eq!(sent(&a).len(), 1, "100s without a good pass is a stall");
    }

    /// A page that was missed is not a page. Still-down is re-announced on
    /// the reminder interval.
    #[test]
    fn a_long_outage_is_reminded() {
        let mut a = alerter();
        for t in [1, 2, 3] {
            a.report("evm", t, Err("rpc".into()));
        }
        assert_eq!(sent(&a).len(), 1);
        a.report("evm", 500, Err("rpc".into()));
        assert_eq!(sent(&a).len(), 1);
        a.report("evm", 1100, Err("rpc".into()));
        assert_eq!(sent(&a).len(), 2);
        assert!(sent(&a)[1].contains("STILL DOWN"));
    }

    /// Without a webhook the journal line is still produced (not captured
    /// here) and nothing panics.
    #[test]
    fn no_sink_is_fine() {
        let mut a: Alerter<Captured> = Alerter::new(None, 11);
        for t in [1, 2, 3, 4] {
            a.report("x", t, Err("e".into()));
        }
        assert!(a.health()[0].down);
    }
}
