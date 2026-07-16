//! IOC-*type* modules — the routing brains.
//!
//! Each module owns one category of indicator and knows how to detect,
//! validate, and normalize (including refanging) its values. The engine
//! classifies a raw IOC by asking each module in turn.

use crate::model::indicator::IndicatorType;

mod crypto;
mod email;
mod file;
mod network;
pub use crypto::CryptoModule;
pub use email::EmailModule;
pub use file::FileModule;
pub use network::NetworkModule;

/// The outcome of classifying a raw value: its type and canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub indicator_type: IndicatorType,
    pub canonical: String,
}

/// An IOC-type module: owns detection, validation and normalization for one
/// category of indicator (network, file, email, ...).
pub trait IocModule: Send + Sync {
    /// Module name (e.g. "network").
    fn name(&self) -> &str;

    /// The indicator types this module can recognize.
    fn handles(&self) -> Vec<IndicatorType>;

    /// Try to classify and normalize a raw value. Returns `Some` if this module
    /// recognizes it, with the detected type and canonical (refanged) form.
    fn detect(&self, raw: &str) -> Option<Detection>;
}

/// The default set of IOC-type modules, in priority order.
pub fn default_modules() -> Vec<Box<dyn IocModule>> {
    // Crypto must precede file: a 32-char legacy BTC address can in principle
    // be all-hex and look like an MD5, and only crypto can checksum-validate it.
    // The other type spaces are disjoint (no dots, no '@', no digest lengths).
    vec![
        Box::new(NetworkModule),
        Box::new(EmailModule),
        Box::new(CryptoModule),
        Box::new(FileModule),
    ]
}

/// Detect the type of a raw IOC by consulting each module in order.
pub fn detect(raw: &str) -> Option<Detection> {
    default_modules().iter().find_map(|m| m.detect(raw))
}
