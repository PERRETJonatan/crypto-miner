//! Work sources: where jobs come from and where solutions go.

pub mod solo;
pub mod stratum;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendConfig {
    Stratum(stratum::StratumConfig),
    Solo(solo::SoloConfig),
}
