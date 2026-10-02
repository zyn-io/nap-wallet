use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequest {
    /// An https URL, or empty for the start page.
    pub url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondRequest {
    pub id: u64,
    /// `{"result": …}` or `{"error": {"code", "message"}}`, as JSON text.
    pub json: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveRequest {
    pub kicker: String,
    pub title: String,
    pub rows: Vec<Vec<String>>,
    pub note: String,
    pub danger: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approved {
    pub approved: bool,
}
