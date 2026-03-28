mod cache;
mod content;
mod context;
mod error;
mod file;
pub(crate) mod keys;
mod orchestrator;

pub use content::is_likely_binary;
pub use error::ScannerError;
pub use keys::{
    KeyFinding, check_pgp_key, check_ssh_key, check_x509_for_private_key, inspect_key_material,
};
pub use orchestrator::run;
