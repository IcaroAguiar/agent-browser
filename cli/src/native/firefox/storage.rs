//! Firefox cookies, web storage and saved state. Formats must match `cookies.rs` and `state.rs`.

use serde_json::Value;

use crate::native::actions::DaemonState;

const NOT_YET: &str = "not yet implemented on Firefox";

/// Returns `{cookies: [...]}` like Chrome's `handle_cookies_get` (via `storage.getCookies`).
pub async fn cookies_get(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Sets cookies like Chrome's `handle_cookies_set` (via `storage.setCookie`).
pub async fn cookies_set(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Clears cookies like Chrome's `handle_cookies_clear` (via `storage.deleteCookies`).
pub async fn cookies_clear(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Reads local or session storage through evaluate, like Chrome's `handle_storage_get`.
pub async fn storage_get(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Writes local or session storage like Chrome's `handle_storage_set`.
pub async fn storage_set(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Clears local or session storage like Chrome's `handle_storage_clear`.
pub async fn storage_clear(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Saves cookies and origin storage in the `state.rs` JSON format, like Chrome's `handle_state_save`.
pub async fn state_save(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// Loads a `state.rs` JSON file, dropping Chrome-only cookie fields, like Chrome's
/// `handle_state_load`. `--session-name` restore reuses this and is not wired for Firefox yet.
pub async fn state_load(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}
