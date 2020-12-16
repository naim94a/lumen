use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    // on connect
    pub connected: DateTime<Utc>,
}
