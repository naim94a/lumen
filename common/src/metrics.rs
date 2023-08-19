use std::sync::atomic::AtomicI64;

use prometheus_client::{registry::Registry, metrics::{gauge::Gauge, family::Family, counter::Counter}, encoding::EncodeLabelSet};

pub struct Metrics {
    pub registry: Registry,

    /// Count active lumina connections
    pub active_connections: Gauge<i64, AtomicI64>,

    /// Record connected client versions
    pub lumina_version: Family<LuminaVersion, Gauge>,

    /// Count new functions pushes
    pub new_funcs: Counter<u64>,

    /// Count pushed functions
    pub pushes: Counter<u64>,

    /// Count pulled functions
    pub pulls: Counter<u64>,
}

#[derive(EncodeLabelSet, Debug, Hash, Eq, PartialEq, Clone)]
pub struct LuminaVersion {
    pub protocol_version: u32,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();

        let active_connections = Gauge::default();
        registry.register("active_connections", "Active Lumina connections", active_connections.clone());

        let lumina_version = Family::<LuminaVersion, Gauge>::default();
        registry.register("lumina_verisons", "Version of Lumina protocol being used", lumina_version.clone());

        let new_funcs = Counter::default();
        registry.register("new_funcs", "Pushes previously unknown functions", new_funcs.clone());

        let pushes = Counter::default();
        registry.register("pushes", "Total pushes functions", pushes.clone());

        let pulls = Counter::default();
        registry.register("pulls", "Total pulled functions", pulls.clone());

        Metrics {
            registry,
            active_connections,
            lumina_version,
            new_funcs,
            pushes,
            pulls,
        }
    }
}
