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
    if let Some(start) = out.find("{{") {
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
    let target = ["url", "selector", "text", "value"]
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
        .ok_or("nothing to save: the flow has no `open <url>` command")?;
    let host = host_of(&start).ok_or("the flow's start URL has no host")?;
    let base = base_domain(&host);

    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    let mut dropped_headers: Vec<String> = Vec::new();
    let mut request_ids: Vec<String> = Vec::new();

    for (index, (seq, cmd)) in input.recorder.commands.iter().enumerate() {
        let tagged: Vec<&HarEntry> = input
            .entries
            .iter()
            .filter(|e| input.recorder.request_tags.get(&e.request_id) == Some(seq))
            .collect();
        let mut requests = Vec::new();
        let mut seen = Vec::new();
        for e in tagged.iter().filter(|e| is_api_entry(e, &base)) {
            let key = format!("{} {}", e.method, e.url);
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
        );
        if requests.is_empty() && interactive {
            let reason = if tagged.is_empty() {
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
        "params": input.params.iter().map(|(k, v)| json!({ "name": k, "example": v })).collect::<Vec<_>>(),
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
        "params": input.params.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        "gaps": gaps,
        "droppedHeaders": dropped_headers,
        "verified": false,
    });
    Ok((flow, report))
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

pub struct PreparedRequest {
    pub id: String,
    pub step: usize,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub expect: Value,
}

/// Requests to send for a run: only the one the flow answers with, since
/// values chained from earlier responses are not tracked yet.
pub fn prepare(
    flow: &Value,
    cmd_params: &[(String, String)],
) -> Result<Vec<PreparedRequest>, String> {
    let output = flow["output"].as_str().unwrap_or("").to_string();
    Ok(prepare_all(flow, cmd_params)?
        .into_iter()
        .filter(|r| output.is_empty() || r.id == output)
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

pub fn is_write(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS")
}

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

/// Tier 1: send the request directly, with cookies from the live session.
pub async fn run_http(
    client: &reqwest::Client,
    req: &PreparedRequest,
    cookie_header: Option<&str>,
) -> TierResult {
    let started = Instant::now();
    let fail_as = |drift: bool, status: Option<u16>, reason: String| TierResult {
        id: req.id.clone(),
        step: req.step,
        ok: false,
        status,
        reason: Some(reason),
        body: None,
        ms: started.elapsed().as_millis(),
        drift,
    };
    let fail = |status: Option<u16>, reason: String| fail_as(true, status, reason);
    let method = match reqwest::Method::from_bytes(req.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return fail(None, format!("unsupported method {}", req.method)),
    };
    let mut builder = client.request(method, &req.url);
    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }
    if let Some(cookie) = cookie_header.filter(|c| !c.is_empty()) {
        builder = builder.header("cookie", cookie);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => return fail_as(false, None, format!("request failed: {}", e)),
    };
    let status = resp.status().as_u16();
    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => return fail(Some(status), format!("could not read body: {}", e)),
    };
    if matches!(status, 401 | 403 | 407 | 429) {
        return fail(Some(status), format!("HTTP {}", status));
    }
    if !(200..300).contains(&status) {
        return fail_as(false, Some(status), format!("HTTP {}", status));
    }
    if looks_like_challenge(&text) {
        return fail(
            Some(status),
            "bot challenge page instead of data".to_string(),
        );
    }
    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return fail(Some(status), "response is not JSON".to_string()),
    };
    if let Err(reason) = signature_matches(&req.expect["signature"], &signature(&parsed)) {
        return fail(Some(status), format!("response shape changed: {}", reason));
    }
    TierResult {
        id: req.id.clone(),
        step: req.step,
        ok: true,
        status: Some(status),
        reason: None,
        body: Some(parsed),
        ms: started.elapsed().as_millis(),
        drift: false,
    }
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

/// Fold tier results into the run response, and stamp the flow when every
/// request passed.
pub fn finish_run(
    flow: &mut Value,
    results: &[TierResult],
    now: &str,
    total_ms: u128,
    shape: &Shape,
) -> Value {
    let all_ok = !results.is_empty() && results.iter().all(|r| r.ok);
    if all_ok {
        flow["verifiedAt"] = json!(now);
    } else if results.iter().any(|r| !r.ok && r.drift) {
        flow["verifiedAt"] = Value::Null;
    }
    let output_id = flow["output"].as_str().unwrap_or("").to_string();
    let output = results
        .iter()
        .find(|r| r.id == output_id)
        .and_then(|r| r.body.clone())
        .map(|b| apply_shape(b, shape));
    let steps: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "step": r.step,
                "tier": if r.ok { json!("http") } else { Value::Null },
                "status": r.status,
                "ms": r.ms,
                "error": r.reason,
            })
        })
        .collect();
    json!({
        "name": flow["name"],
        "origin": flow["origin"],
        "ok": all_ok,
        "verified": all_ok,
        "ms": total_ms,
        "steps": steps,
        "data": output,
    })
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
}
