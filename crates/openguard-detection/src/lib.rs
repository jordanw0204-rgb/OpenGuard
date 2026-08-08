#![forbid(unsafe_code)]

mod risk;
mod scan;

pub use risk::{BehaviorContext, RiskEnvironment, assess_process, correlate_behavior};
pub use scan::{FileScanner, HashOutcome, ScanError, hash_file};
