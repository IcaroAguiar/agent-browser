//! Firefox tab and window commands. Tab ids are BiDi browsing context UUIDs.

use serde_json::{json, Value};

use super::actions::session;
use crate::native::actions::DaemonState;

const NOT_YET: &str = "not yet implemented on Firefox";

/// Opens a tab and makes it active. Must return what Chrome's `handle_tab_new` returns,
/// honouring `url` and `label`.
pub async fn tab_new(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Lists top-level tabs as `{tabs: [{tabId, targetId, label, title, url, type, active}]}`.
pub async fn tab_list(state: &mut DaemonState) -> Result<Value, String> {
    let ff = session(state)?;
    let tree = ff
        .bidi
        .send("browsingContext.getTree", json!({"maxDepth": 0}))
        .await?;
    let mut tabs = Vec::new();
    for c in tree["contexts"].as_array().into_iter().flatten() {
        let id = c["context"].as_str().unwrap_or_default();
        let title = ff
            .bidi
            .call_function(id, "() => document.title", None, vec![])
            .await
            .unwrap_or(Value::Null);
        tabs.push(json!({
            "tabId": id,
            "targetId": id,
            "label": ff.tab_labels.get(id),
            "title": title,
            "url": c["url"],
            "type": "page",
            "active": id == ff.context,
        }));
    }
    Ok(json!({ "tabs": tabs }))
}

/// Switches the active tab by context UUID or label. Must return what Chrome's
/// `handle_tab_switch` returns and clear `state.ref_map` and `ff.refs` after the switch commits.
pub async fn tab_switch(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Closes a tab (the active one without `tabId`). Must return what Chrome's `handle_tab_close`
/// returns and refuse to close the last tab.
pub async fn tab_close(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Opens a new window. Must return what Chrome's `handle_window_new` returns.
pub async fn window_new(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}
