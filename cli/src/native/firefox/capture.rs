//! Firefox screenshots and PDF.

use serde_json::Value;

use crate::native::actions::DaemonState;

const NOT_YET: &str = "not yet implemented on Firefox";

/// Viewport or full-page screenshot (`browsingContext.captureScreenshot`, `origin: document` for
/// full page). Must return what Chrome's `handle_screenshot` returns for the same flags.
pub async fn screenshot(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}

/// PDF of the active tab (`browsingContext.print`). Must return what Chrome's `handle_pdf` returns.
pub async fn pdf(_cmd: &Value, _state: &mut DaemonState) -> Result<Value, String> {
    Err(NOT_YET.into())
}
