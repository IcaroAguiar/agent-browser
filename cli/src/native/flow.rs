//! Saved flows: record a task once in the browser, then replay its
//! first-party API requests directly over HTTP.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::actions::HarEntry;

pub const FLOW_VERSION: u64 = 1;

/// Commands and request tags captured between `flow start` and `flow save`.
#[derive(Default)]
pub struct FlowRecorder {
    pub name: Option<String>,
    pub commands: Vec<(u64, Value)>,
    /// HAR request id to the sequence number of the command that was
    /// running when the request started.
    pub request_tags: HashMap<String, u64>,
    pub current_seq: Option<u64>,
    pub started_har: bool,
    /// The tab's URL when recording began, for flows that start on an open page.
    pub page_url: Option<String>,
    next_seq: u64,
}

impl FlowRecorder {
    pub fn active(&self) -> bool {
        self.name.is_some()
    }

    pub fn start(&mut self, name: &str, started_har: bool) {
        *self = FlowRecorder {
            name: Some(name.to_string()),
            started_har,
            page_url: None,
            ..FlowRecorder::default()
        };
    }

    pub fn begin_command(&mut self, action: &str, cmd: &Value) {
        if !self.active() || !is_recordable(action) {
            return;
        }
        self.next_seq += 1;
        let mut recorded = cmd.clone();
        if let Some(obj) = recorded.as_object_mut() {
            obj.remove("id");
        }
        self.commands.push((self.next_seq, recorded));
        self.current_seq = Some(self.next_seq);
    }

    pub fn tag_request(&mut self, request_id: &str) {
        if let Some(seq) = self.current_seq {
            self.request_tags.insert(request_id.to_string(), seq);
        }
    }
}

fn is_recordable(action: &str) -> bool {
    !(action.is_empty()
        || action.starts_with("flow_")
        || action.starts_with("har_")
        || matches!(
            action,
            "close" | "session_info" | "requests" | "request_detail" | "cookies_get"
        ))
}

// ---------------------------------------------------------------------------
// Request selection
// ---------------------------------------------------------------------------

const TELEMETRY_PATH_MARKERS: &[&str] = &[
    "/collect",
    "/track",
    "/beacon",
    "/analytics",
    "/pixel",
    "/telemetry",
    "/metrics",
    "/log",
    "/rum",
    "/sentry",
];

const DROPPED_HEADERS: &[&str] = &[
    "cookie",
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "authorization",
    "proxy-authorization",
];

/// Registrable part of a host, close enough for first-party checks:
/// `api.example.com.ar` -> `example.com.ar`, `www.example.org` -> `example.org`.
pub fn base_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let second_level = labels[labels.len() - 2];
    let tld = labels[labels.len() - 1];
    let keep = if tld.len() == 2
        && matches!(
            second_level,
            "com" | "co" | "org" | "net" | "gov" | "gob" | "edu" | "ac"
        ) {
        3
    } else {
        2
    };
    labels[labels.len() - keep..].join(".")
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(String::from)
}

fn is_first_party(url: &str, base: &str) -> bool {
    host_of(url)
        .map(|h| h == base || h.ends_with(&format!(".{}", base)))
        .unwrap_or(false)
}

fn is_telemetry(url: &str) -> bool {
    let path = url::Url::parse(url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    TELEMETRY_PATH_MARKERS
        .iter()
        .any(|m| path == *m || path.starts_with(&format!("{}/", m)) || path.ends_with(m))
}

fn is_api_entry(e: &HarEntry, base: &str) -> bool {
    matches!(e.resource_type.as_str(), "XHR" | "Fetch")
        && e.mime_type.contains("json")
        && e.status.map(|s| (200..300).contains(&s)).unwrap_or(false)
        && is_first_party(&e.url, base)
        && !is_telemetry(&e.url)
}

// ---------------------------------------------------------------------------
// Response signatures
// ---------------------------------------------------------------------------

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

const SIGNATURE_DEPTH: usize = 3;

/// Shape of a JSON body, a few levels deep: object keys with their types,
/// and the element shape for arrays.
pub fn signature(v: &Value) -> Value {
    signature_at(v, SIGNATURE_DEPTH)
}

fn signature_at(v: &Value, depth: usize) -> Value {
    match v {
        Value::Object(map) if depth > 0 => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sig = Map::new();
            for k in keys {
                sig.insert(k.clone(), signature_at(&map[k], depth - 1));
            }
            json!({ "object": sig })
        }
        Value::Array(items) if depth > 0 => match items.first() {
            Some(first) => json!({ "array": signature_at(first, depth - 1) }),
            None => json!({ "array": null }),
        },
        other => json!({ "scalar": type_name(other) }),
    }
}

fn signature_type(sig: &Value) -> &str {
    if sig.get("object").is_some() {
        "object"
    } else if sig.get("array").is_some() {
        "array"
    } else {
        sig.get("scalar")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown")
    }
}

/// Every key the recording saw must still be there with the same type. New
/// keys are fine; a missing or retyped key means the contract moved.
pub fn signature_matches(recorded: &Value, current: &Value) -> Result<(), String> {
    matches_at(recorded, current, "")
}

fn matches_at(recorded: &Value, current: &Value, path: &str) -> Result<(), String> {
    let (rec_ty, cur_ty) = (signature_type(recorded), signature_type(current));
    if rec_ty == "null" || cur_ty == "null" {
        return Ok(());
    }
    if rec_ty != cur_ty {
        let at = if path.is_empty() {
            "response".to_string()
        } else {
            format!("'{}'", path)
        };
        return Err(format!("{} changed from {} to {}", at, rec_ty, cur_ty));
    }
    if let (Some(rec), Some(cur)) = (
        recorded.get("object").and_then(|v| v.as_object()),
        current.get("object").and_then(|v| v.as_object()),
    ) {
        for (key, sig) in rec {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", path, key)
            };
            match cur.get(key) {
                None => return Err(format!("key '{}' is missing", child)),
                Some(cur_sig) => matches_at(sig, cur_sig, &child)?,
            }
        }
    }
    if let (Some(rec), Some(cur)) = (recorded.get("array"), current.get("array")) {
        if !rec.is_null() && !cur.is_null() {
            matches_at(rec, cur, &format!("{}[]", path))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Params
// ---------------------------------------------------------------------------

pub fn parse_params(cmd: &Value) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    if let Some(obj) = cmd.get("params").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            let value = v
                .as_str()
                .ok_or(format!("param '{}' must be a string", k))?;
            out.push((k.clone(), value.to_string()));
        }
    }
    Ok(out)
}

fn templatize(text: &str, params: &[(String, String)], encoded: bool) -> String {
    let mut out = text.to_string();
    for (name, value) in params {
        if value.is_empty() {
            continue;
        }
        let needle = if encoded {
            urlencoding::encode(value).into_owned()
        } else {
            value.clone()
        };
        out = out.replace(&needle, &format!("{{{{{}}}}}", name));
        if encoded && needle != *value {
            out = out.replace(value.as_str(), &format!("{{{{{}}}}}", name));
        }
    }
    out
}

fn fill(template: &str, params: &HashMap<String, String>, encoded: bool) -> Result<String, String> {
    let mut out = template.to_string();
    for (name, value) in params {
        let v = if encoded {
            urlencoding::encode(value).into_owned()
        } else {
            value.clone()
        };
        out = out.replace(&format!("{{{{{}}}}}", name), &v);
    }
    if let Some(start) = out
        .match_indices("{{")
        .map(|(i, _)| i)
        .find(|i| !out[*i..].starts_with("{{@"))
    {
        if let Some(len) = out[start..].find("}}") {
            return Err(format!("missing --param {}", &out[start + 2..start + len]));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Save
// ---------------------------------------------------------------------------

pub struct SaveInput<'a> {
    pub name: &'a str,
    pub recorder: &'a FlowRecorder,
    pub entries: &'a [HarEntry],
    pub params: &'a [(String, String)],
    pub output: Option<&'a str>,
    pub created_at: String,
    /// The page shows a password field at save time.
    pub login_wall: bool,
}

fn start_url(commands: &[(u64, Value)]) -> Option<String> {
    commands.iter().find_map(|(_, c)| {
        (c.get("action").and_then(|a| a.as_str()) == Some("navigate"))
            .then(|| c.get("url").and_then(|u| u.as_str()).map(String::from))
            .flatten()
    })
}

fn describe_command(cmd: &Value) -> String {
    let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("?");
    let target = ["url", "selector", "name", "text", "value"]
        .iter()
        .find_map(|k| cmd.get(*k).and_then(|v| v.as_str()));
    match target {
        Some(t) => format!("{} {}", action, t),
        None => action.to_string(),
    }
}

/// Build the flow file and the save report from what was recorded.
pub fn build_flow(input: SaveInput<'_>) -> Result<(Value, Value), String> {
    let start = start_url(&input.recorder.commands)
        .or_else(|| {
            input
                .recorder
                .page_url
                .clone()
                .filter(|u| u.starts_with("http"))
        })
        .ok_or("nothing to save: the flow has no `open <url>` command and no page was open")?;
    let host = host_of(&start).ok_or("the flow's start URL has no host")?;
    let base = base_domain(&host);

    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    let mut dropped_headers: Vec<String> = Vec::new();
    let mut request_ids: Vec<String> = Vec::new();
    let mut bodies: Vec<(String, Value)> = Vec::new();

    for (index, (seq, cmd)) in input.recorder.commands.iter().enumerate() {
        let tagged: Vec<&HarEntry> = input
            .entries
            .iter()
            .filter(|e| input.recorder.request_tags.get(&e.request_id) == Some(seq))
            .collect();
        let mut requests = Vec::new();
        let mut seen = Vec::new();
        for e in tagged.iter().filter(|e| is_api_entry(e, &base)) {
            let key = format!(
                "{} {} {}",
                e.method,
                e.url,
                e.post_data.as_deref().unwrap_or("")
            );
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let Some(body) = e
                .response_body
                .as_deref()
                .filter(|_| !e.response_body_base64)
            else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<Value>(body) else {
                continue;
            };
            let mut headers = Map::new();
            for (k, v) in &e.request_headers {
                let lower = k.to_ascii_lowercase();
                if lower.starts_with(':') {
                    continue;
                }
                if DROPPED_HEADERS.contains(&lower.as_str())
                    || lower.contains("token")
                    || lower.contains("csrf")
                {
                    if !dropped_headers.contains(&lower) && lower != "host" {
                        dropped_headers.push(lower);
                    }
                    continue;
                }
                headers.insert(k.clone(), json!(templatize(v, input.params, false)));
            }
            let item_fields = item_fields(&parsed);
            let id = format!("s{}r{}", index + 1, requests.len() + 1);
            bodies.push((id.clone(), parsed.clone()));
            request_ids.push(id.clone());
            requests.push(json!({
                "id": id,
                "method": e.method,
                "url": templatize(&e.url, input.params, true),
                "headers": headers,
                "body": e.post_data.as_deref().map(|b| templatize(b, input.params, false)),
                "expect": {
                    "status": e.status,
                    "mime": e.mime_type,
                    "signature": signature(&parsed),
                    "bytes": body.len(),
                    "itemFields": item_fields,
                },
            }));
        }
        let action = cmd.get("action").and_then(|a| a.as_str()).unwrap_or("");
        let interactive = matches!(
            action,
            "navigate"
                | "click"
                | "dblclick"
                | "fill"
                | "type"
                | "press"
                | "select"
                | "check"
                | "uncheck"
                | "submit"
                | "getbyrole"
        );
        if requests.is_empty() && interactive {
            let reason = if input.login_wall && index + 1 == input.recorder.commands.len() {
                "the page asked for a login; this step needs an account, and the flow stops before it"
            } else if tagged.is_empty() {
                "no network traffic while this command ran"
            } else if tagged.iter().any(|e| is_first_party(&e.url, &base)) {
                "first-party traffic was documents or static files, not a JSON API"
            } else {
                "only third-party traffic"
            };
            gaps.push(
                json!({ "step": index + 1, "command": describe_command(cmd), "reason": reason }),
            );
        }
        steps.push(json!({ "command": cmd, "requests": requests }));
    }

    if request_ids.is_empty() {
        return Err(format!(
            "no first-party JSON requests were recorded for {}; this flow has nothing to replay over HTTP",
            base
        ));
    }
    let links = link_requests(&mut steps, &bodies, input.params);
    let mut params: Vec<Value> = input
        .params
        .iter()
        .map(|(k, v)| json!({ "name": k, "example": v }))
        .collect();
    params.extend(links.params.iter().cloned());
    let output = match input.output {
        Some(id) if request_ids.iter().any(|r| r == id) => id.to_string(),
        Some(id) => return Err(format!("unknown request id '{}' for --output", id)),
        None => default_output(&steps),
    };

    let flow = json!({
        "version": FLOW_VERSION,
        "name": input.name,
        "origin": host,
        "startUrl": start,
        "createdAt": input.created_at,
        "params": params,
        "output": output,
        "itemFields": steps
            .iter()
            .flat_map(|s| s["requests"].as_array().into_iter().flatten())
            .find(|r| r["id"] == output.as_str())
            .map(|r| r["expect"]["itemFields"].clone())
            .unwrap_or(json!([])),
        "provenance": "observed",
        "verifiedAt": Value::Null,
        "steps": steps,
    });

    let requests_report: Vec<Value> = flow["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|s| s["requests"].as_array().cloned().unwrap_or_default())
        .map(|r| {
            json!({
                "id": r["id"],
                "method": r["method"],
                "url": r["url"],
                "bytes": r["expect"]["bytes"],
            })
        })
        .collect();

    let report = json!({
        "name": input.name,
        "origin": host,
        "steps": input.recorder.commands.len(),
        "requests": requests_report,
        "output": output,
        "params": params.iter().map(|p| p["name"].clone()).collect::<Vec<_>>(),
        "detectedParams": links.params,
        "references": links.references,
        "gaps": gaps,
        "droppedHeaders": dropped_headers,
        "verified": false,
    });
    Ok((flow, report))
}

// ---------------------------------------------------------------------------
// Params and references found in the recording
// ---------------------------------------------------------------------------

struct Links {
    /// Values that came from an item of an earlier list: the agent picks one.
    params: Vec<Value>,
    /// Values that came from a single field of an earlier response: filled in
    /// at run time from that response.
    references: Vec<Value>,
}

/// Values a request sends: query values, path segments and JSON body scalars.
fn sent_values(req: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(url) = url::Url::parse(req["url"].as_str().unwrap_or("")) {
        out.extend(url.query_pairs().map(|(_, v)| v.into_owned()));
        if let Some(segs) = url.path_segments() {
            out.extend(segs.map(|s| {
                urlencoding::decode(s)
                    .map(|d| d.into_owned())
                    .unwrap_or_default()
            }));
        }
    }
    if let Some(body) = req["body"]
        .as_str()
        .and_then(|b| serde_json::from_str::<Value>(b).ok())
    {
        collect_scalars(&body, &mut out);
    }
    // Short values (ids like "1", flags like "es") match unrelated fields by chance.
    out.retain(|v| v.chars().count() >= 3 && !v.contains("{{"));
    out.sort();
    out.dedup();
    out
}

fn collect_scalars(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => m.values().for_each(|c| collect_scalars(c, out)),
        Value::Array(a) => a.iter().for_each(|c| collect_scalars(c, out)),
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
}

/// Where `needle` sits in `body`, as a path like `token` or `data[].sessionId`,
/// and whether the path crosses a list.
fn find_value(body: &Value, needle: &str, path: &str) -> Option<(String, bool)> {
    match body {
        Value::Object(m) => m.iter().find_map(|(k, v)| {
            let child = if path.is_empty() {
                k.clone()
            } else {
                format!("{}.{}", path, k)
            };
            find_value(v, needle, &child)
        }),
        Value::Array(a) => a
            .iter()
            .find_map(|v| find_value(v, needle, &format!("{}[]", path)))
            .map(|(p, _)| (p, true)),
        Value::String(s) if s == needle => Some((path.to_string(), false)),
        Value::Number(n) if n.to_string() == needle => Some((path.to_string(), false)),
        _ => None,
    }
}

fn link_requests(
    steps: &mut [Value],
    bodies: &[(String, Value)],
    given: &[(String, String)],
) -> Links {
    let mut links = Links {
        params: Vec::new(),
        references: Vec::new(),
    };
    let given_values: Vec<&str> = given.iter().map(|(_, v)| v.as_str()).collect();
    let order: Vec<String> = bodies.iter().map(|(id, _)| id.clone()).collect();
    for step in steps.iter_mut() {
        let Some(requests) = step["requests"].as_array_mut() else {
            continue;
        };
        for req in requests.iter_mut() {
            let id = req["id"].as_str().unwrap_or("").to_string();
            let earlier = &bodies[..order.iter().position(|o| *o == id).unwrap_or(0)];
            for value in sent_values(req) {
                if given_values.contains(&value.as_str()) {
                    continue;
                }
                let Some((from, path, in_list)) = earlier.iter().rev().find_map(|(from, body)| {
                    find_value(body, &value, "").map(|(p, l)| (from.clone(), p, l))
                }) else {
                    continue;
                };
                let placeholder = if in_list {
                    let field = path
                        .rsplit(['.', ']'])
                        .next()
                        .unwrap_or("value")
                        .to_string();
                    let name = match links.params.iter().find(|p| p["example"] == value.as_str()) {
                        Some(p) => p["name"].as_str().unwrap_or("").to_string(),
                        None => {
                            let mut name = field.clone();
                            let mut n = 2;
                            while links.params.iter().any(|p| p["name"] == name.as_str())
                                || given.iter().any(|(k, _)| *k == name)
                            {
                                name = format!("{}{}", field, n);
                                n += 1;
                            }
                            links.params.push(json!({
                                "name": name,
                                "example": value,
                                "from": { "request": from, "list": path },
                            }));
                            name
                        }
                    };
                    format!("{{{{{}}}}}", name)
                } else {
                    links
                        .references
                        .push(json!({ "request": id, "from": from, "path": path }));
                    format!("{{{{@{}.{}}}}}", from, path)
                };
                for key in ["url", "body"] {
                    if let Some(text) = req[key].as_str() {
                        let encoded = urlencoding::encode(&value).into_owned();
                        let replaced = text
                            .replace(&encoded, &placeholder)
                            .replace(&value, &placeholder);
                        req[key] = json!(replaced);
                    }
                }
            }
        }
    }
    links
}

/// Values a reference placeholder in `text` points at, filled from the
/// responses already received in this run.
pub fn fill_references(
    text: &str,
    bodies: &HashMap<String, Value>,
    encoded: bool,
) -> Result<String, String> {
    let mut out = text.to_string();
    while let Some(start) = out.find("{{@") {
        let Some(len) = out[start..].find("}}") else {
            break;
        };
        let inner = out[start + 3..start + len].to_string();
        let (from, path) = inner
            .split_once('.')
            .ok_or(format!("bad reference {}", inner))?;
        let body = bodies
            .get(from)
            .ok_or(format!("reference to {} before it ran", from))?;
        let value = lookup(body, path)
            .map(as_text)
            .ok_or(format!("{} no longer has '{}'", from, path))?;
        let value = if encoded {
            urlencoding::encode(&value).into_owned()
        } else {
            value
        };
        out.replace_range(start..start + len + 2, &value);
    }
    Ok(out)
}

/// Request ids a request needs answers from, in run order.
pub fn dependencies(flow: &Value, id: &str) -> Vec<String> {
    let requests: Vec<&Value> = flow["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|s| s["requests"].as_array().into_iter().flatten())
        .collect();
    let refs_of = |rid: &str| -> Vec<String> {
        requests
            .iter()
            .find(|r| r["id"] == rid)
            .map(|r| {
                let text = format!(
                    "{} {}",
                    r["url"].as_str().unwrap_or(""),
                    r["body"].as_str().unwrap_or("")
                );
                text.match_indices("{{@")
                    .filter_map(|(i, _)| text[i + 3..].split('.').next().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut needed = vec![id.to_string()];
    let mut i = 0;
    while i < needed.len() {
        for dep in refs_of(&needed[i].clone()) {
            if !needed.contains(&dep) {
                needed.push(dep);
            }
        }
        i += 1;
    }
    requests
        .iter()
        .filter_map(|r| r["id"].as_str())
        .filter(|r| needed.iter().any(|n| n == r))
        .map(String::from)
        .collect()
}

/// Field names an agent can pass to `--where` and `--fields`: the keys of the
/// first item of the response's main list, with one level of dotted paths.
fn item_fields(body: &Value) -> Vec<String> {
    let Some((_, items)) = main_list(body) else {
        return Vec::new();
    };
    let Some(first) = items.first().and_then(|i| i.as_object()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, v) in first {
        match v.as_object() {
            Some(child) if !child.is_empty() => {
                out.extend(child.keys().map(|c| format!("{}.{}", k, c)))
            }
            _ => out.push(k.clone()),
        }
    }
    out
}

/// The request the flow answers with when the agent does not pick one: the
/// largest response among requests that use a param, else the largest.
fn default_output(steps: &[Value]) -> String {
    let requests: Vec<&Value> = steps
        .iter()
        .flat_map(|s| s["requests"].as_array().into_iter().flatten())
        .collect();
    let uses_param = |r: &&Value| {
        r["url"].as_str().unwrap_or("").contains("{{")
            || r["body"].as_str().unwrap_or("").contains("{{")
    };
    let pool: Vec<&Value> = if requests.iter().any(uses_param) {
        requests.iter().copied().filter(uses_param).collect()
    } else {
        requests
    };
    pool.iter()
        .max_by_key(|r| r["expect"]["bytes"].as_u64().unwrap_or(0))
        .and_then(|r| r["id"].as_str())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Output shaping
// ---------------------------------------------------------------------------

/// `--where field=value` (case-insensitive substring), `--fields a,b.c`, `--limit n`.
#[derive(Default)]
pub struct Shape {
    pub filters: Vec<(String, String)>,
    pub fields: Vec<String>,
    pub limit: Option<usize>,
}

impl Shape {
    pub fn from_cmd(cmd: &Value) -> Shape {
        let filters = cmd
            .get("where")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let fields = cmd
            .get("fields")
            .and_then(|v| v.as_str())
            .map(|f| {
                f.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let limit = cmd
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize);
        Shape {
            filters,
            fields,
            limit,
        }
    }

    fn is_empty(&self) -> bool {
        self.filters.is_empty() && self.fields.is_empty() && self.limit.is_none()
    }
}

fn lookup<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, key| cur.get(key))
}

fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The list the response is about: the body itself if it is an array, else
/// its largest array field.
fn main_list(body: &Value) -> Option<(Option<String>, &Vec<Value>)> {
    if let Some(items) = body.as_array() {
        return Some((None, items));
    }
    body.as_object()?
        .iter()
        .filter_map(|(k, v)| v.as_array().map(|a| (Some(k.clone()), a)))
        .max_by_key(|(_, a)| a.len())
}

/// Field names used in `--where` or `--fields` that no item has.
pub fn unknown_fields(body: &Value, shape: &Shape) -> Vec<String> {
    let Some((_, items)) = main_list(body) else {
        return Vec::new();
    };
    shape
        .filters
        .iter()
        .map(|(f, _)| f)
        .chain(shape.fields.iter())
        .filter(|f| !items.iter().any(|item| lookup(item, f).is_some()))
        .cloned()
        .collect()
}

pub fn apply_shape(body: Value, shape: &Shape) -> Value {
    if shape.is_empty() {
        return body;
    }
    let Some((key, items)) = main_list(&body) else {
        return body;
    };
    let total = items.len();
    let mut kept: Vec<Value> = items
        .iter()
        .filter(|item| {
            shape.filters.iter().all(|(path, needle)| {
                lookup(item, path)
                    .map(|v| as_text(v).to_lowercase().contains(needle.as_str()))
                    .unwrap_or(false)
            })
        })
        .map(|item| {
            if shape.fields.is_empty() {
                return item.clone();
            }
            let mut out = Map::new();
            for f in &shape.fields {
                if let Some(v) = lookup(item, f) {
                    out.insert(f.clone(), v.clone());
                }
            }
            Value::Object(out)
        })
        .collect();
    let matched = kept.len();
    if let Some(limit) = shape.limit {
        kept.truncate(limit);
    }
    json!({ "list": key, "total": total, "matched": matched, "items": kept })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

pub fn flows_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AGENT_BROWSER_FLOWS_DIR") {
        return PathBuf::from(dir);
    }
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".agent-browser")
        .join("flows")
}

fn valid_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "invalid flow name '{}': use letters, digits, '-' or '_'",
            name
        ));
    }
    Ok(())
}

pub fn validate_name(name: &str) -> Result<(), String> {
    valid_name(name)
}

pub fn flow_path(origin: &str, name: &str) -> PathBuf {
    flows_dir().join(origin).join(format!("{}.json", name))
}

pub fn write_flow(flow: &Value) -> Result<PathBuf, String> {
    let origin = flow["origin"].as_str().ok_or("flow has no origin")?;
    let name = flow["name"].as_str().ok_or("flow has no name")?;
    let path = flow_path(origin, name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }
    let text = serde_json::to_string_pretty(flow).map_err(|e| e.to_string())?;
    std::fs::write(&path, text)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    Ok(path)
}

pub fn list_flows(origin: Option<&str>) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(origins) = std::fs::read_dir(flows_dir()) else {
        return out;
    };
    let mut dirs: Vec<_> = origins.flatten().filter(|d| d.path().is_dir()).collect();
    dirs.sort_by_key(|d| d.file_name());
    for dir in dirs {
        let dir_origin = dir.file_name().to_string_lossy().to_string();
        if let Some(o) = origin {
            if base_domain(o) != base_domain(&dir_origin) {
                continue;
            }
        }
        let Ok(files) = std::fs::read_dir(dir.path()) else {
            continue;
        };
        let mut files: Vec<_> = files.flatten().collect();
        files.sort_by_key(|f| f.file_name());
        for f in files {
            let Ok(text) = std::fs::read_to_string(f.path()) else {
                continue;
            };
            let Ok(flow) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            out.push(json!({
                "name": flow["name"],
                "origin": flow["origin"],
                "params": flow["params"].as_array().map(|ps| ps.iter().map(|p| p["name"].clone()).collect::<Vec<_>>()).unwrap_or_default(),
                "examples": flow["params"].as_array().map(|ps| ps.iter().filter_map(|p| Some((p["name"].as_str()?.to_string(), p["example"].clone()))).collect::<Map<String, Value>>()).unwrap_or_default(),
                "paramSources": flow["params"].as_array().map(|ps| ps.iter().filter_map(|p| Some((p["name"].as_str()?.to_string(), json!(format!("{} {}", p["from"]["request"].as_str()?, p["from"]["list"].as_str()?))))).collect::<Map<String, Value>>()).unwrap_or_default(),
                "itemFields": flow["itemFields"],
                "recordedOn": flow["startUrl"],
                "provenance": flow["provenance"],
                "verifiedAt": flow["verifiedAt"],
            }));
        }
    }
    out
}

pub fn load_flow(name: &str, origin: Option<&str>) -> Result<Value, String> {
    valid_name(name)?;
    let matches: Vec<Value> = list_flows(origin)
        .into_iter()
        .filter(|f| f["name"] == name)
        .collect();
    match matches.as_slice() {
        [] => Err(format!(
            "no saved flow named '{}'. Run `flow list` to see saved flows",
            name
        )),
        [one] => {
            let path = flow_path(one["origin"].as_str().unwrap_or_default(), name);
            let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            serde_json::from_str(&text)
                .map_err(|e| format!("{} is not valid JSON: {}", path.display(), e))
        }
        many => Err(format!(
            "flow '{}' exists for several origins ({}); pass --origin",
            name,
            many.iter()
                .filter_map(|f| f["origin"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PreparedRequest {
    pub id: String,
    pub step: usize,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub expect: Value,
}

/// Requests to send for a run: the one the flow answers with, and the ones
/// whose responses it takes values from.
pub fn prepare(
    flow: &Value,
    cmd_params: &[(String, String)],
) -> Result<Vec<PreparedRequest>, String> {
    let output = flow["output"].as_str().unwrap_or("").to_string();
    let needed = dependencies(flow, &output);
    Ok(prepare_all(flow, cmd_params)?
        .into_iter()
        .filter(|r| output.is_empty() || needed.contains(&r.id))
        .collect())
}

pub fn prepare_all(
    flow: &Value,
    cmd_params: &[(String, String)],
) -> Result<Vec<PreparedRequest>, String> {
    let mut params: HashMap<String, String> = flow["params"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            Some((
                p["name"].as_str()?.to_string(),
                p["example"].as_str()?.to_string(),
            ))
        })
        .collect();
    let known: Vec<String> = params.keys().cloned().collect();
    for (k, v) in cmd_params {
        if !known.contains(k) {
            return Err(format!(
                "flow '{}' has no param '{}' (params: {})",
                flow["name"].as_str().unwrap_or(""),
                k,
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            ));
        }
        params.insert(k.clone(), v.clone());
    }

    let mut out = Vec::new();
    for (index, step) in flow["steps"].as_array().into_iter().flatten().enumerate() {
        for r in step["requests"].as_array().into_iter().flatten() {
            let headers = r["headers"]
                .as_object()
                .map(|h| {
                    h.iter()
                        .filter_map(|(k, v)| {
                            Some((k.clone(), fill(v.as_str()?, &params, false).ok()?))
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(PreparedRequest {
                id: r["id"].as_str().unwrap_or("").to_string(),
                step: index + 1,
                method: r["method"].as_str().unwrap_or("GET").to_string(),
                url: fill(r["url"].as_str().unwrap_or(""), &params, true)?,
                headers,
                body: match r["body"].as_str() {
                    Some(b) => Some(fill(b, &params, false)?),
                    None => None,
                },
                expect: r["expect"].clone(),
            });
        }
    }
    Ok(out)
}

impl PreparedRequest {
    /// Fill reference placeholders from the responses received so far.
    pub fn resolve(&self, bodies: &HashMap<String, Value>) -> Result<PreparedRequest, String> {
        let mut out = self.clone();
        out.url = fill_references(&self.url, bodies, true)?;
        if let Some(b) = &self.body {
            out.body = Some(fill_references(b, bodies, false)?);
        }
        Ok(out)
    }
}

pub fn is_write(method: &str, body: Option<&str>) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS") && !is_graphql_query(body)
}

/// A GraphQL POST that only runs queries reads data; mutations still count
/// as writes.
fn is_graphql_query(body: Option<&str>) -> bool {
    let Some(parsed) = body.and_then(|b| serde_json::from_str::<Value>(b).ok()) else {
        return false;
    };
    let ops: Vec<&Value> = match &parsed {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    !ops.is_empty()
        && ops.iter().all(|op| {
            op["query"].as_str().is_some_and(|q| {
                let q = q.trim_start();
                (q.starts_with("query") || q.starts_with('{')) && !q.contains("mutation")
            })
        })
}

pub const TIERS: &[&str] = &["http", "page", "replay"];

pub struct TierResult {
    pub id: String,
    pub step: usize,
    pub ok: bool,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub body: Option<Value>,
    pub ms: u128,
    /// The failure says the site or its gate changed, not that the inputs were wrong.
    pub drift: bool,
    /// The response came back with a different shape than the recording.
    pub shape_changed: bool,
    pub tier: &'static str,
}

impl TierResult {
    fn failed(req: &PreparedRequest, tier: &'static str, ms: u128, f: Failure) -> TierResult {
        TierResult {
            id: req.id.clone(),
            step: req.step,
            ok: false,
            status: f.status,
            reason: Some(f.reason),
            body: None,
            ms,
            drift: f.drift,
            shape_changed: f.shape_changed,
            tier,
        }
    }
}

pub struct Failure {
    pub status: Option<u16>,
    pub reason: String,
    pub drift: bool,
    pub shape_changed: bool,
}

impl Failure {
    fn new(drift: bool, status: Option<u16>, reason: String) -> Failure {
        Failure {
            status,
            reason,
            drift,
            shape_changed: false,
        }
    }
}

fn looks_like_challenge(body: &str) -> bool {
    let head: String = body
        .chars()
        .take(4000)
        .collect::<String>()
        .to_ascii_lowercase();
    [
        "cf-chl",
        "captcha",
        "challenge-platform",
        "px-captcha",
        "_incapsula_",
    ]
    .iter()
    .any(|m| head.contains(m))
}

/// Judge a response the same way on every tier: blocked, rejected input,
/// changed shape, or data.
pub fn check_response(req: &PreparedRequest, status: u16, text: &str) -> Result<Value, Failure> {
    if matches!(status, 401 | 403 | 407 | 429) {
        return Err(Failure::new(true, Some(status), format!("HTTP {}", status)));
    }
    if !(200..300).contains(&status) {
        return Err(Failure::new(
            false,
            Some(status),
            format!("HTTP {}", status),
        ));
    }
    if looks_like_challenge(text) {
        return Err(Failure::new(
            true,
            Some(status),
            "bot challenge page instead of data".to_string(),
        ));
    }
    let parsed: Value = serde_json::from_str(text)
        .map_err(|_| Failure::new(true, Some(status), "response is not JSON".to_string()))?;
    if let Err(reason) = signature_matches(&req.expect["signature"], &signature(&parsed)) {
        return Err(Failure {
            status: Some(status),
            reason: format!("response shape changed: {}", reason),
            drift: true,
            shape_changed: true,
        });
    }
    Ok(parsed)
}

pub fn tier_result(
    req: &PreparedRequest,
    tier: &'static str,
    started: Instant,
    outcome: Result<(u16, String), Failure>,
) -> TierResult {
    let ms = started.elapsed().as_millis();
    let checked = outcome
        .and_then(|(status, text)| check_response(req, status, &text).map(|body| (status, body)));
    match checked {
        Ok((status, body)) => TierResult {
            id: req.id.clone(),
            step: req.step,
            ok: true,
            status: Some(status),
            reason: None,
            body: Some(body),
            ms,
            drift: false,
            shape_changed: false,
            tier,
        },
        Err(f) => TierResult::failed(req, tier, ms, f),
    }
}

/// A session route (`network route`) that matches the request answers it on
/// the HTTP tier too, so mocks apply to the whole session.
pub struct RoutedResponse {
    pub abort: bool,
    pub status: u16,
    pub body: String,
}

/// Tier 1: send the request directly, with cookies from the live session.
pub async fn run_http(
    client: &reqwest::Client,
    req: &PreparedRequest,
    cookie_header: Option<&str>,
    routed: Option<RoutedResponse>,
) -> TierResult {
    let started = Instant::now();
    if let Some(r) = routed {
        let outcome = if r.abort {
            Err(Failure::new(
                false,
                None,
                "request aborted by a session route".to_string(),
            ))
        } else {
            Ok((r.status, r.body))
        };
        return tier_result(req, "http", started, outcome);
    }
    let method = match reqwest::Method::from_bytes(req.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return tier_result(
                req,
                "http",
                started,
                Err(Failure::new(
                    true,
                    None,
                    format!("unsupported method {}", req.method),
                )),
            )
        }
    };
    let mut builder = client.request(method, &req.url);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    if let Some(cookie) = cookie_header.filter(|c| !c.is_empty()) {
        builder = builder.header("cookie", cookie);
    }
    // Browsers send Origin on every write; sites check it against CSRF.
    let has_origin = req
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("origin"));
    if is_write(&req.method, req.body.as_deref()) && !has_origin {
        if let Some(origin) = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
            .and_then(|(_, v)| url::Url::parse(v).ok())
            .map(|u| u.origin().ascii_serialization())
        {
            builder = builder.header("origin", origin);
        }
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    let outcome = match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            resp.text().await.map(|t| (status, t)).map_err(|e| {
                Failure::new(true, Some(status), format!("could not read body: {}", e))
            })
        }
        Err(e) => Err(Failure::new(false, None, format!("request failed: {}", e))),
    };
    tier_result(req, "http", started, outcome)
}

/// Tier 2: the page sends the request itself, so the browser adds its own
/// cookies, client hints and any headers the site's scripts would not.
pub fn page_fetch_script(req: &PreparedRequest) -> String {
    // Headers the browser sets itself. Sending them as app headers turns the
    // request into a CORS preflight the site never allowed.
    let browser_set = |k: &str| {
        let k = k.to_ascii_lowercase();
        k.starts_with("sec-")
            || matches!(
                k.as_str(),
                "user-agent" | "referer" | "origin" | "accept-language" | "priority" | "dnt"
            )
    };
    let headers: Map<String, Value> = req
        .headers
        .iter()
        .filter(|(k, _)| !browser_set(k))
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    let init = json!({
        "method": req.method,
        "headers": headers,
        "body": req.body,
    });
    // Cross-origin APIs differ on credentials: some need cookies, some reject
    // a credentialed request outright. Try with, then without.
    format!(
        "(async () => {{ const u = {url}, i = {init}; \
         let r; try {{ r = await fetch(u, {{ ...i, credentials: 'include' }}); }} \
         catch (e) {{ r = await fetch(u, i); }} \
         return {{ status: r.status, text: await r.text() }}; }})()",
        url = json!(req.url),
        init = init
    )
}

pub fn page_result(
    req: &PreparedRequest,
    started: Instant,
    value: Result<Value, String>,
) -> TierResult {
    let outcome = match value {
        Ok(v) => match (v["status"].as_u64(), v["text"].as_str()) {
            (Some(status), Some(text)) => Ok((status as u16, text.to_string())),
            _ => Err(Failure::new(
                true,
                None,
                "in-page fetch returned no response".to_string(),
            )),
        },
        Err(e) => Err(Failure::new(
            true,
            None,
            format!("in-page fetch failed: {}", e),
        )),
    };
    tier_result(req, "page", started, outcome)
}

/// Tier 3: the recorded commands with the run's params swapped in. A param
/// whose recorded value no command contains cannot be replayed: the browser
/// would answer with the recorded value instead.
pub fn replay_commands(
    flow: &Value,
    cmd_params: &[(String, String)],
) -> Result<Vec<Value>, String> {
    let swaps: Vec<(String, String)> = flow["params"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let name = p["name"].as_str()?;
            let example = p["example"].as_str()?;
            let value = cmd_params.iter().find(|(k, _)| k == name)?.1.clone();
            (!example.is_empty() && example != value).then(|| (example.to_string(), value))
        })
        .collect();
    let recorded = serde_json::to_string(
        &flow["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| s["command"].clone())
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default();
    if let Some((from, _)) = swaps.iter().find(|(from, _)| {
        !recorded.contains(from.as_str()) && !recorded.contains(urlencoding::encode(from).as_ref())
    }) {
        let name = flow["params"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| p["example"].as_str() == Some(from.as_str()))
            .and_then(|p| p["name"].as_str())
            .unwrap_or("?");
        return Err(format!(
            "param '{}' is not in the recorded commands, so a replay would return the recorded value {}",
            name, from
        ));
    }
    let opens_page = flow["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| s["command"]["action"] == "navigate");
    // A flow recorded on an already open page starts from that page.
    let start = (!opens_page)
        .then(|| flow["startUrl"].as_str())
        .flatten()
        .map(|u| json!({ "action": "navigate", "url": u }));
    Ok(start
        .into_iter()
        .chain(
            flow["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| {
                    let mut text = serde_json::to_string(&s["command"]).ok()?;
                    for (from, to) in &swaps {
                        text = text.replace(from.as_str(), to);
                        let (ef, et) = (urlencoding::encode(from), urlencoding::encode(to));
                        if ef != *from {
                            text = text.replace(ef.as_ref(), et.as_ref());
                        }
                    }
                    serde_json::from_str(&text).ok()
                }),
        )
        .collect())
}

/// The entry captured during a replay that stands for a recorded request:
/// same method, host and path, and for requests with a body the same body or
/// GraphQL operation (one endpoint serves every query). An exact URL wins.
pub fn replay_match<'a>(entries: &'a [HarEntry], req: &PreparedRequest) -> Option<&'a HarEntry> {
    let key = |u: &str| {
        url::Url::parse(u)
            .ok()
            .map(|u| (u.host_str().unwrap_or("").to_string(), u.path().to_string()))
    };
    let operation = |b: Option<&str>| {
        b.and_then(|b| serde_json::from_str::<Value>(b).ok())
            .and_then(|v| v["operationName"].as_str().map(String::from))
    };
    let want = key(&req.url);
    let want_op = operation(req.body.as_deref());
    let same_body = |e: &HarEntry| match &req.body {
        None => true,
        Some(b) => {
            e.post_data.as_deref() == Some(b.as_str())
                || (want_op.is_some() && operation(e.post_data.as_deref()) == want_op)
        }
    };
    let candidates: Vec<&HarEntry> = entries
        .iter()
        .rev()
        .filter(|e| e.method == req.method && key(&e.url) == want && same_body(e))
        .collect();
    candidates
        .iter()
        .find(|e| e.url == req.url)
        .or_else(|| candidates.first())
        .copied()
}

pub fn replay_result(
    req: &PreparedRequest,
    started: Instant,
    entry: Option<&HarEntry>,
) -> TierResult {
    let outcome = match entry {
        None => Err(Failure::new(
            true,
            None,
            "replaying the recorded commands did not send this request".to_string(),
        )),
        Some(e) => match (e.status, e.response_body.as_deref()) {
            (Some(status), Some(body)) if !e.response_body_base64 => {
                Ok((status as u16, body.to_string()))
            }
            (Some(status), _) => Err(Failure::new(
                true,
                Some(status as u16),
                "the replayed request has no readable body".to_string(),
            )),
            _ => Err(Failure::new(
                true,
                None,
                "the replayed request got no response".to_string(),
            )),
        },
    };
    tier_result(req, "replay", started, outcome)
}

pub fn replay_failed(req: &PreparedRequest, started: Instant, reason: String) -> TierResult {
    tier_result(
        req,
        "replay",
        started,
        Err(Failure::new(true, None, reason)),
    )
}

/// The replay tier cannot express this run; that says nothing about the site.
pub fn replay_unavailable(req: &PreparedRequest, started: Instant, reason: String) -> TierResult {
    tier_result(
        req,
        "replay",
        started,
        Err(Failure::new(false, None, reason)),
    )
}

/// A reference the run could not fill: the earlier response changed.
pub fn unresolved(req: &PreparedRequest, reason: String) -> TierResult {
    tier_result(
        req,
        "http",
        Instant::now(),
        Err(Failure::new(true, None, reason)),
    )
}

/// Tiers to try for a request, starting from the one that last worked.
pub fn tiers_for(flow: &Value, id: &str) -> Vec<&'static str> {
    let preferred = flow["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|s| s["requests"].as_array().into_iter().flatten())
        .find(|r| r["id"] == id)
        .and_then(|r| r["tier"].as_str())
        .and_then(|t| TIERS.iter().position(|x| *x == t))
        .unwrap_or(0);
    TIERS[preferred..].to_vec()
}

pub fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

pub fn cookie_header(cookies: &[super::cookies::Cookie]) -> String {
    cookies
        .iter()
        .map(|c| format!("{}={}", c.name, c.value))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Fold tier results into the run response. `attempts` holds every tier
/// tried, in order; the last attempt per request is the one that counts.
/// The flow is verified only when every request came back with the recorded
/// shape and no tier saw that shape change.
pub fn finish_run(
    flow: &mut Value,
    attempts: &[TierResult],
    now: &str,
    total_ms: u128,
    shape: &Shape,
) -> Value {
    let mut last: Vec<&TierResult> = Vec::new();
    for a in attempts {
        match last.iter().position(|r| r.id == a.id) {
            Some(i) => last[i] = a,
            None => last.push(a),
        }
    }
    let all_ok = !last.is_empty() && last.iter().all(|r| r.ok);
    let shape_changed = attempts.iter().find(|a| a.shape_changed);
    if all_ok && shape_changed.is_none() {
        flow["verifiedAt"] = json!(now);
    } else if shape_changed.is_some() || (!all_ok && attempts.iter().any(|r| !r.ok && r.drift)) {
        flow["verifiedAt"] = Value::Null;
    }
    // Remember the tier that worked, so the next run starts there.
    for r in last.iter().filter(|r| r.ok) {
        if let Some(steps) = flow["steps"].as_array_mut() {
            for req in steps
                .iter_mut()
                .flat_map(|s| s["requests"].as_array_mut().into_iter().flatten())
                .filter(|req| req["id"] == r.id.as_str())
            {
                if r.tier == TIERS[0] {
                    if let Some(o) = req.as_object_mut() {
                        o.remove("tier");
                    }
                } else {
                    req["tier"] = json!(r.tier);
                }
            }
        }
    }
    let output_id = flow["output"].as_str().unwrap_or("").to_string();
    let output = last
        .iter()
        .find(|r| r.id == output_id && r.ok)
        .and_then(|r| r.body.clone())
        .map(|b| apply_shape(b, shape));
    let steps: Vec<Value> = last
        .iter()
        .map(|r| {
            let fell_back: Vec<Value> = attempts
                .iter()
                .filter(|a| a.id == r.id && !std::ptr::eq(*a, *r))
                .map(|a| json!({ "tier": a.tier, "error": a.reason }))
                .collect();
            let mut step = json!({
                "id": r.id,
                "step": r.step,
                "tier": if r.ok { json!(r.tier) } else { Value::Null },
                "status": r.status,
                "ms": r.ms,
                "error": r.reason,
            });
            if !fell_back.is_empty() {
                step["fellBack"] = json!(fell_back);
            }
            step
        })
        .collect();
    let mut response = json!({
        "name": flow["name"],
        "origin": flow["origin"],
        "ok": all_ok,
        "verified": all_ok && shape_changed.is_none(),
        "ms": total_ms,
        "steps": steps,
        "data": output,
    });
    if let Some(a) = shape_changed {
        response["drift"] = json!({ "tier": a.tier, "step": a.step, "reason": a.reason });
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, url: &str, rtype: &str, mime: &str, body: &str) -> HarEntry {
        HarEntry {
            request_id: id.to_string(),
            wall_time: 0.0,
            method: "GET".to_string(),
            url: url.to_string(),
            request_headers: vec![
                ("Accept".to_string(), "application/json".to_string()),
                ("Cookie".to_string(), "session=secret".to_string()),
                ("X-CSRF-Token".to_string(), "abc".to_string()),
            ],
            post_data: None,
            request_body_size: 0,
            resource_type: rtype.to_string(),
            status: Some(200),
            status_text: "OK".to_string(),
            http_version: "HTTP/2.0".to_string(),
            response_headers: Vec::new(),
            mime_type: mime.to_string(),
            redirect_url: String::new(),
            response_body_size: body.len() as i64,
            cdp_timing: None,
            loading_finished_timestamp: None,
            response_body: Some(body.to_string()),
            response_body_base64: false,
        }
    }

    fn recorder() -> FlowRecorder {
        let mut r = FlowRecorder::default();
        r.start("showtimes", true);
        r.begin_command(
            "navigate",
            &json!({ "id": "1", "action": "navigate", "url": "https://www.example.com.ar/" }),
        );
        r.tag_request("doc");
        r.tag_request("api");
        r.tag_request("ga");
        r.begin_command(
            "click",
            &json!({ "id": "2", "action": "click", "selector": "@e4" }),
        );
        r
    }

    #[test]
    fn base_domain_handles_second_level_country_domains() {
        assert_eq!(base_domain("api.example.com.ar"), "example.com.ar");
        assert_eq!(base_domain("www.example.org"), "example.org");
        assert_eq!(base_domain("example.org"), "example.org");
        assert_eq!(base_domain("app.example.io"), "example.io");
    }

    #[test]
    fn save_keeps_first_party_json_and_drops_credentials() {
        let rec = recorder();
        let entries = vec![
            entry(
                "doc",
                "https://www.example.com.ar/",
                "Document",
                "text/html",
                "<html>",
            ),
            entry(
                "api",
                "https://api.example.com.ar/movies?film=Film%20One",
                "Fetch",
                "application/json",
                r#"{"movies":[{"id":1}],"total":1}"#,
            ),
            entry(
                "ga",
                "https://www.google-analytics.com/collect",
                "XHR",
                "application/json",
                "{}",
            ),
        ];
        let params = vec![("film".to_string(), "Film One".to_string())];
        let (flow, report) = build_flow(SaveInput {
            name: "showtimes",
            recorder: &rec,
            entries: &entries,
            params: &params,
            output: None,
            created_at: "2026-10-26T00:00:00Z".to_string(),
            login_wall: false,
        })
        .unwrap();
        let req = &flow["steps"][0]["requests"][0];
        assert_eq!(
            req["url"],
            "https://api.example.com.ar/movies?film={{film}}"
        );
        assert!(req["headers"].get("Cookie").is_none());
        assert!(req["headers"].get("X-CSRF-Token").is_none());
        assert_eq!(flow["steps"][0]["requests"].as_array().unwrap().len(), 1);
        assert_eq!(flow["output"], "s1r1");
        assert_eq!(flow["verifiedAt"], Value::Null);
        assert!(!serde_json::to_string(&flow).unwrap().contains("secret"));
        assert_eq!(report["gaps"][0]["step"], 2);
        assert_eq!(
            report["gaps"][0]["reason"],
            "no network traffic while this command ran"
        );
    }

    #[test]
    fn save_fails_without_api_traffic() {
        let rec = recorder();
        let entries = vec![entry(
            "doc",
            "https://www.example.com.ar/",
            "Document",
            "text/html",
            "<html>",
        )];
        let err = build_flow(SaveInput {
            name: "showtimes",
            recorder: &rec,
            entries: &entries,
            params: &[],
            output: None,
            created_at: String::new(),
            login_wall: false,
        })
        .unwrap_err();
        assert!(err.contains("no first-party JSON requests"));
    }

    #[test]
    fn signature_detects_removed_and_retyped_keys() {
        let rec = signature(&json!({ "movies": [], "total": 1 }));
        assert!(signature_matches(
            &rec,
            &signature(&json!({ "movies": [], "total": 2, "extra": true }))
        )
        .is_ok());
        assert!(signature_matches(&rec, &signature(&json!({ "total": 2 })))
            .unwrap_err()
            .contains("movies"));
        assert!(signature_matches(&rec, &signature(&json!({ "movies": {}, "total": 2 }))).is_err());
        assert!(signature_matches(&rec, &signature(&json!([1]))).is_err());
    }

    #[test]
    fn shape_filters_by_substring_and_picks_fields() {
        let body = json!({ "data": [
            { "movieName": "FILM ALPHA", "room": "5", "occupation": { "free": 10 } },
            { "movieName": "FILM BETA", "room": "2", "occupation": { "free": 3 } },
        ] });
        let shape = Shape {
            filters: vec![("movieName".to_string(), "alpha".to_string())],
            fields: vec!["room".to_string(), "occupation.free".to_string()],
            limit: None,
        };
        let out = apply_shape(body, &shape);
        assert_eq!(out["total"], 2);
        assert_eq!(out["matched"], 1);
        assert_eq!(
            out["items"][0],
            json!({ "room": "5", "occupation.free": 10 })
        );
    }

    #[test]
    fn signature_catches_nested_changes() {
        let rec =
            signature(&json!({ "data": [{ "movieName": "x", "occupation": { "seats": 1 } }] }));
        let moved = signature(&json!({ "data": [{ "title": "x", "occupation": { "seats": 1 } }] }));
        assert!(signature_matches(&rec, &moved)
            .unwrap_err()
            .contains("data[].movieName"));
    }

    #[test]
    fn prepare_fills_params_and_rejects_unknown_ones() {
        let flow = json!({
            "name": "showtimes",
            "params": [{ "name": "film", "example": "Film One" }],
            "output": "s1r1",
            "steps": [{ "requests": [{ "id": "s1r1", "method": "GET", "url": "https://site.example/m?film={{film}}", "headers": {}, "body": null, "expect": {} }] }],
        });
        let reqs = prepare(&flow, &[("film".to_string(), "Film Two".to_string())]).unwrap();
        assert_eq!(reqs[0].url, "https://site.example/m?film=Film%20Two");
        let reqs = prepare(&flow, &[]).unwrap();
        assert_eq!(reqs[0].url, "https://site.example/m?film=Film%20One");
        assert!(prepare(&flow, &[("city".to_string(), "x".to_string())]).is_err());
    }

    #[test]
    fn recorder_ignores_flow_and_har_commands() {
        let mut r = FlowRecorder::default();
        r.begin_command("click", &json!({}));
        assert!(r.commands.is_empty());
        r.start("x", false);
        r.begin_command("flow_save", &json!({}));
        r.begin_command("har_start", &json!({}));
        r.begin_command("click", &json!({ "id": "9", "action": "click" }));
        assert_eq!(r.commands.len(), 1);
        assert!(r.commands[0].1.get("id").is_none());
    }

    fn prepared(id: &str) -> PreparedRequest {
        PreparedRequest {
            id: id.to_string(),
            step: 1,
            method: "GET".to_string(),
            url: "https://api.site.example/m?film=Film".to_string(),
            headers: vec![
                ("User-Agent".to_string(), "x".to_string()),
                ("sec-ch-ua".to_string(), "x".to_string()),
                ("country".to_string(), "AR".to_string()),
            ],
            body: None,
            expect: json!({ "signature": signature(&json!({ "data": [{ "id": 1 }] })) }),
        }
    }

    fn attempt(
        id: &str,
        tier: &'static str,
        outcome: Result<(u16, String), Failure>,
    ) -> TierResult {
        tier_result(&prepared(id), tier, Instant::now(), outcome)
    }

    #[test]
    fn check_response_separates_blocks_inputs_and_shape_changes() {
        let req = prepared("s1r1");
        let blocked = check_response(&req, 403, "").unwrap_err();
        assert!(blocked.drift && !blocked.shape_changed);
        let rejected = check_response(&req, 400, "{}").unwrap_err();
        assert!(!rejected.drift);
        let moved = check_response(&req, 200, r#"{"items":[]}"#).unwrap_err();
        assert!(moved.drift && moved.shape_changed);
        assert!(check_response(&req, 200, r#"{"data":[{"id":2}]}"#).is_ok());
    }

    #[test]
    fn a_blocked_tier_falls_back_and_the_flow_stays_verified() {
        let mut flow = json!({
            "name": "f", "origin": "site.example", "output": "s1r1", "verifiedAt": null,
            "steps": [{ "requests": [{ "id": "s1r1" }] }],
        });
        let attempts = vec![
            attempt("s1r1", "http", Ok((403, String::new()))),
            attempt(
                "s1r1",
                "page",
                Ok((200, r#"{"data":[{"id":1}]}"#.to_string())),
            ),
        ];
        let out = finish_run(&mut flow, &attempts, "now", 1, &Shape::default());
        assert_eq!(out["verified"], true);
        assert_eq!(out["steps"][0]["tier"], "page");
        assert_eq!(out["steps"][0]["fellBack"][0]["tier"], "http");
        assert_eq!(flow["verifiedAt"], "now");
        assert_eq!(flow["steps"][0]["requests"][0]["tier"], "page");
        assert_eq!(tiers_for(&flow, "s1r1"), vec!["page", "replay"]);
    }

    #[test]
    fn a_changed_shape_marks_the_flow_unverified_even_if_a_lower_tier_answers() {
        let mut flow = json!({
            "name": "f", "origin": "site.example", "output": "s1r1", "verifiedAt": "before",
            "steps": [{ "requests": [{ "id": "s1r1" }] }],
        });
        let attempts = vec![
            attempt("s1r1", "http", Ok((200, r#"{"items":[]}"#.to_string()))),
            attempt(
                "s1r1",
                "page",
                Ok((200, r#"{"data":[{"id":1}]}"#.to_string())),
            ),
        ];
        let out = finish_run(&mut flow, &attempts, "now", 1, &Shape::default());
        assert_eq!(out["ok"], true);
        assert_eq!(out["verified"], false);
        assert_eq!(out["drift"]["tier"], "http");
        assert_eq!(flow["verifiedAt"], Value::Null);
    }

    #[test]
    fn a_rejected_input_keeps_the_flow_verified() {
        let mut flow = json!({
            "name": "f", "origin": "site.example", "output": "s1r1", "verifiedAt": "before",
            "steps": [{ "requests": [{ "id": "s1r1" }] }],
        });
        let attempts = vec![attempt("s1r1", "http", Ok((400, "{}".to_string())))];
        let out = finish_run(&mut flow, &attempts, "now", 1, &Shape::default());
        assert_eq!(out["ok"], false);
        assert_eq!(flow["verifiedAt"], "before");
    }

    #[test]
    fn page_fetch_leaves_browser_headers_to_the_browser() {
        let script = page_fetch_script(&prepared("s1r1"));
        assert!(script.contains("country"));
        assert!(!script.contains("User-Agent"));
        assert!(!script.contains("sec-ch-ua"));
    }

    #[test]
    fn replay_swaps_params_into_commands_and_refuses_missing_ones() {
        let flow = json!({
            "params": [{ "name": "q", "example": "film one" }],
            "steps": [
                { "command": { "action": "navigate", "url": "https://site.example/search?q=film%20one" } },
                { "command": { "action": "fill", "selector": "#q", "value": "film one" } },
            ],
        });
        let cmds = replay_commands(&flow, &[("q".to_string(), "other".to_string())]).unwrap();
        assert_eq!(cmds[0]["url"], "https://site.example/search?q=other");
        assert_eq!(cmds[1]["value"], "other");
        let hidden = json!({
            "params": [{ "name": "theater", "example": "401" }],
            "steps": [{ "command": { "action": "navigate", "url": "https://site.example/downtown" } }],
        });
        assert!(
            replay_commands(&hidden, &[("theater".to_string(), "402".to_string())])
                .unwrap_err()
                .contains("theater")
        );
        assert!(replay_commands(&hidden, &[]).is_ok());
    }

    #[test]
    fn save_turns_list_values_into_params_and_single_values_into_references() {
        let mut r = FlowRecorder::default();
        r.start("seats", true);
        r.begin_command(
            "navigate",
            &json!({ "action": "navigate", "url": "https://www.example.com.ar/" }),
        );
        for id in ["theaters", "token", "seats"] {
            r.tag_request(id);
        }
        let entries = vec![
            entry(
                "theaters",
                "https://api.example.com.ar/theaters",
                "Fetch",
                "application/json",
                r#"{"data":[{"theaterId":"401"},{"theaterId":"402"}]}"#,
            ),
            entry(
                "token",
                "https://api.example.com.ar/session",
                "Fetch",
                "application/json",
                r#"{"session":{"key":"k-81f2"}}"#,
            ),
            entry(
                "seats",
                "https://api.example.com.ar/seats?theater=401&key=k-81f2",
                "Fetch",
                "application/json",
                r#"{"seats":[{"row":"A"}]}"#,
            ),
        ];
        let (flow, report) = build_flow(SaveInput {
            name: "seats",
            recorder: &r,
            entries: &entries,
            params: &[],
            output: Some("s1r3"),
            created_at: String::new(),
            login_wall: false,
        })
        .unwrap();
        let seats = &flow["steps"][0]["requests"][2];
        assert_eq!(
            seats["url"],
            "https://api.example.com.ar/seats?theater={{theaterId}}&key={{@s1r2.session.key}}"
        );
        assert_eq!(
            report["detectedParams"][0]["from"]["list"],
            "data[].theaterId"
        );
        assert_eq!(report["references"][0]["path"], "session.key");
        assert_eq!(dependencies(&flow, "s1r3"), vec!["s1r2", "s1r3"]);

        let reqs = prepare(&flow, &[("theaterId".to_string(), "402".to_string())]).unwrap();
        assert_eq!(reqs.len(), 2);
        let mut bodies = HashMap::new();
        bodies.insert("s1r2".to_string(), json!({ "session": { "key": "k 2" } }));
        let filled = reqs[1].resolve(&bodies).unwrap();
        assert_eq!(
            filled.url,
            "https://api.example.com.ar/seats?theater=402&key=k%202"
        );
        assert!(reqs[1].resolve(&HashMap::new()).is_err());
    }

    #[test]
    fn a_login_wall_names_the_last_gap() {
        let rec = recorder();
        let entries = vec![entry(
            "api",
            "https://api.example.com.ar/movies",
            "Fetch",
            "application/json",
            r#"{"movies":[]}"#,
        )];
        let (_, report) = build_flow(SaveInput {
            name: "showtimes",
            recorder: &rec,
            entries: &entries,
            params: &[],
            output: None,
            created_at: String::new(),
            login_wall: true,
        })
        .unwrap();
        assert!(report["gaps"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("login"));
    }

    #[test]
    fn graphql_queries_are_reads_and_mutations_are_writes() {
        assert!(!is_write("GET", None));
        assert!(is_write("POST", Some(r#"{"a":1}"#)));
        assert!(!is_write(
            "POST",
            Some(r#"{"query":"query appConfig { x }"}"#)
        ));
        assert!(!is_write("POST", Some(r#"[{"query":"{ me { id } }"}]"#)));
        assert!(is_write(
            "POST",
            Some(r#"{"query":"mutation buy { order }"}"#)
        ));
    }

    #[test]
    fn replay_match_tells_graphql_operations_apart() {
        let mut a = entry(
            "a",
            "https://api.site.example/graphql",
            "Fetch",
            "application/json",
            "{}",
        );
        a.method = "POST".to_string();
        a.post_data = Some(r#"{"operationName":"appConfig","variables":{}}"#.to_string());
        let mut b = a.clone();
        b.request_id = "b".to_string();
        b.post_data = Some(r#"{"operationName":"positions","variables":{"t":2}}"#.to_string());
        let mut req = prepared("s1r1");
        req.method = "POST".to_string();
        req.url = "https://api.site.example/graphql".to_string();
        req.body = Some(r#"{"operationName":"positions","variables":{"t":1}}"#.to_string());
        let entries = vec![b, a];
        assert_eq!(replay_match(&entries, &req).unwrap().request_id, "b");
        req.body = Some(r#"{"operationName":"other"}"#.to_string());
        assert!(replay_match(&entries, &req).is_none());
    }
}
