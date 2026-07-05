//! AEGIS-MESH Core Library v0.2 — audited and remediated.

#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod config;
pub mod crypto;
pub mod error;
pub mod mesh;
pub mod messaging;
pub mod storage;
pub mod transport;

pub use error::{AegisError, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
