#![forbid(unsafe_code)]

mod capabilities;
mod risk;
mod scan;

pub use capabilities::{CapabilityAssessment, inspect_capabilities};
pub use risk::{BehaviorContext, RiskEnvironment, assess_process, correlate_behavior};
pub use scan::{FileScanner, HashOutcome, ScanError, hash_file};
