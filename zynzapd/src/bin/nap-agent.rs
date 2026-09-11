//! Machine-readable access to Nap's restricted agent service.
//!
//! The CLI has no node address, key path, generic HTTP method, or raw RPC
//! escape hatch. Nap owns the session key and makes every policy decision.

use serde_json::{json, Value};

const SCHEMA: &str = "nap.agent.v1";

fn emit(value: &Value) {
    println!("{value}");
}

fn fail(message: &str, code: i32) -> ! {
    eprintln!("nap-agent: {message}");
    emit(&json!({ "schema": SCHEMA, "ok": false, "error": message, "data": {} }));
    std::process::exit(code);
}

fn usage() -> ! {
    fail("usage: nap-agent <status|portfolio|assets|pools|offers|anchors|mandates|quote|draft-swap|check-swap|execute-swap|action|pause|close> ...", 2)
}

fn raw(value: Option<&String>, name: &str) -> String {
    let value = value.unwrap_or_else(|| fail(&format!("missing {name}"), 2));
    value.parse::<i128>().unwrap_or_else(|_| fail(&format!("invalid {name}"), 2));
    value.clone()
}

fn id(value: Option<&String>, name: &str) -> String {
    let value = value.unwrap_or_else(|| fail(&format!("missing {name}"), 2));
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')) {
        fail(&format!("invalid {name}"), 2);
    }
    value.clone()
}

fn number(value: Option<&String>, name: &str) -> u32 {
    value.unwrap_or_else(|| fail(&format!("missing {name}"), 2)).parse().unwrap_or_else(|_| fail(&format!("invalid {name}"), 2))
}

fn path(value: Option<&String>) -> Vec<u32> {
    let value = value.unwrap_or_else(|| fail("missing pool path", 2));
    let pools: Vec<u32> = value.split(',').map(|v| v.parse()).collect::<Result<_, _>>().unwrap_or_else(|_| fail("invalid pool path", 2));
    if pools.is_empty() || pools.len() > 8 { fail("pool path must contain 1-8 pool ids", 2); }
    pools
}

fn swap(args: &[String]) -> Value {
    if args.len() != 4 { fail("swap fields: <asset-in> <pool-id,...> <amount-in-raw> <min-out-raw>", 2); }
    json!({
        "asset_in": number(args.first(), "asset-in"),
        "path": path(args.get(1)),
        "amount_in_raw": raw(args.get(2), "amount-in-raw"),
        "min_out_raw": raw(args.get(3), "min-out-raw"),
    })
}

struct Service {
    base: String,
    token: String,
}

impl Service {
    fn call(&self, method: &str, route: &str, body: Value) -> Result<Value, String> {
        let url = format!("{}/api/agent/{}", self.base.trim_end_matches('/'), route);
        let response = match method {
            "GET" => ureq::get(&url).set("X-Nap-Agent-Token", &self.token).call(),
            "POST" => ureq::post(&url).set("X-Nap-Agent-Token", &self.token).send_json(body),
            _ => unreachable!(),
        };
        match response {
            Ok(r) => r.into_json().map_err(|e| format!("invalid service response: {e}")),
            Err(ureq::Error::Status(_, r)) => {
                let message = r.into_json::<Value>().ok().and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string)).unwrap_or_else(|| "agent service refused the call".into());
                Err(message)
            }
            Err(e) => Err(format!("agent service unavailable: {e}")),
        }
    }
}

fn main() {
    let service = Service {
        base: std::env::var("NAP_AGENT_URL").unwrap_or_else(|_| "http://127.0.0.1:8978".into()),
        token: std::env::var("ZYN_AGENT_TOKEN").unwrap_or_else(|_| fail("ZYN_AGENT_TOKEN is required", 4)),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else { usage() };
    let result = match command {
        "status" | "portfolio" | "assets" | "pools" | "offers" | "anchors" | "mandates" if args.len() == 1 => service.call("GET", command, json!({})),
        "quote" if args.len() == 4 => service.call("POST", "quote", json!({ "asset_in": number(args.get(1), "asset-in"), "path": path(args.get(2)), "amount_in_raw": raw(args.get(3), "amount-in-raw") })),
        "draft-swap" if args.len() == 5 => service.call("POST", "draft-swap", swap(&args[1..])),
        "check-swap" if args.len() == 6 => {
            let mut body = swap(&args[2..]);
            body["mandate_id"] = json!(id(args.get(1), "mandate-id"));
            service.call("POST", "check-swap", body)
        }
        "execute-swap" if args.len() == 7 => {
            let mut body = swap(&args[3..]);
            body["request_id"] = json!(id(args.get(1), "request-id"));
            body["mandate_id"] = json!(id(args.get(2), "mandate-id"));
            service.call("POST", "execute-swap", body)
        }
        "action" if args.len() == 2 => service.call("POST", "action", json!({ "request_id": id(args.get(1), "request-id") })),
        "pause" | "close" if args.len() == 2 => service.call("POST", command, json!({ "mandate_id": id(args.get(1), "mandate-id") })),
        _ => usage(),
    };
    match result {
        Ok(value) => emit(&json!({ "schema": SCHEMA, "ok": true, "data": value, "error": null })),
        Err(error) => fail(&error, if error.contains("unavailable") { 4 } else { 3 }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_arguments_are_structured_and_do_not_include_an_account() {
        let args = vec!["0".into(), "1,4".into(), "100".into(), "90".into()];
        let value = swap(&args);
        assert_eq!(value["path"], json!([1, 4]));
        assert!(value.get("account").is_none());
        assert!(value.get("method").is_none());
        assert!(value.get("rpc").is_none());
    }
}
