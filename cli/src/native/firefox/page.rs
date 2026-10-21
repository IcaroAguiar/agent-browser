//! Page-level Firefox commands: navigation, history, reading page state, evaluate and wait.

use serde_json::{json, Value};

use super::actions::session;
use crate::native::actions::DaemonState;

const NOT_YET: &str = "not yet implemented on Firefox";

/// Turns an `about:neterror?e=...&d=...` URL into the message Firefox shows for the failure.
fn neterror_message(url: &str) -> Option<String> {
    if !url.starts_with("about:neterror") {
        return None;
    }
    let parsed = url::Url::parse(url).ok()?;
    let pair = |key: &str| {
        parsed
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
            .filter(|v| !v.is_empty())
    };
    let code = pair("e").unwrap_or_else(|| "unknown error".to_string());
    Some(match pair("d") {
        Some(detail) => format!("{code}: {detail}"),
        None => code,
    })
}

/// Navigates the active tab and returns `{url, title, targetId}` like `BrowserManager::navigate`.
/// `waitUntil` maps to the BiDi `wait` state.
pub async fn navigate(cmd: &Value, state: &mut DaemonState) -> Result<Value, String> {
    let url = cmd
        .get("url")
        .and_then(Value::as_str)
        .ok_or("Missing 'url' parameter")?;
    let wait = match cmd.get("waitUntil").and_then(Value::as_str) {
        Some("domcontentloaded") => "interactive",
        Some("none") => "none",
        _ => "complete",
    };
    state.ref_map.invalidate_all_documents();
    state.active_frame_id = None;
    let ff = session(state)?;
    ff.refs.clear();
    let context = ff.context.clone();
    let nav = ff
        .race_prompt(ff.bidi.send(
            "browsingContext.navigate",
            json!({"context": context, "url": url, "wait": wait}),
        ))
        .await
        .map_err(|e| format!("Navigation failed: {e}"))?;
    let Some(nav) = nav else {
        let url = ff.url().await.unwrap_or_default();
        return Ok(json!({ "url": url, "targetId": context, "dialogOpened": true }));
    };
    let landed = nav["url"].as_str().unwrap_or(url);
    if let Some(msg) = neterror_message(landed) {
        return Err(format!("Navigation failed: {msg}"));
    }
    let title = ff.eval("document.title").await.unwrap_or(Value::Null);
    Ok(json!({ "url": landed, "title": title, "targetId": context }))
}

/// History back. Must return what Chrome's `handle_back` returns.
pub async fn back(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// History forward. Must return what Chrome's `handle_forward` returns.
pub async fn forward(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Reload. Must return what Chrome's `handle_reload` returns.
pub async fn reload(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Current URL as `{url}`.
pub async fn url(state: &mut DaemonState) -> Result<Value, String> {
    Ok(json!({ "url": session(state)?.url().await? }))
}

/// Document title as `{title}`.
pub async fn title(state: &mut DaemonState) -> Result<Value, String> {
    Ok(json!({ "title": session(state)?.eval("document.title").await? }))
}

/// Page HTML. Must return `{html, origin}` like Chrome's `handle_content`.
pub async fn content(_state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Evaluates `script` and returns `{result, origin}` like Chrome's `handle_evaluate`.
pub async fn evaluate(cmd: &Value, state: &mut DaemonState) -> Result<Value, String> {
    let script = cmd
        .get("script")
        .and_then(Value::as_str)
        .ok_or("Missing 'script' parameter")?;
    let ff = session(state)?;
    let result = ff.eval(script).await?;
    let origin = ff.url().await.unwrap_or_default();
    Ok(json!({ "result": result, "origin": origin }))
}

/// Waits for ms, selector, text, load state, function or URL. Must return the same
/// `{waited: ...}` shapes as Chrome's `handle_wait`, honouring `state.timeout_ms(cmd)`.
pub async fn wait(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neterror_url_becomes_a_message() {
        let url = "about:neterror?e=dnsNotFound&u=https%3A//nope.invalid/&d=We%20can%27t%20connect";
        assert_eq!(
            neterror_message(url).unwrap(),
            "dnsNotFound: We can't connect"
        );
        assert_eq!(
            neterror_message("about:neterror?e=connectionFailure").unwrap(),
            "connectionFailure"
        );
        assert!(neterror_message("https://example.com").is_none());
    }
}
