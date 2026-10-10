//! Cachette — GitHub Actions cache server (v1 artifactcache + Twirp v2) on
//! one port.
//!
//! The library crate exists so integration tests can drive the router and the
//! shared types directly; the binary in `main.rs` wires them to a listener.

pub mod cli;
pub mod error;
pub mod logging;
pub mod routes;
pub mod state;
pub mod storage;
