//! ParolNet relay server library surface.
//!
//! Exposes items that integration tests and downstream tooling need.
//! Application glue lives in `main.rs`.

pub mod frames;
pub mod identity;
pub mod rate_limit;
pub mod storage;
pub mod telemetry;
pub mod ws_conn;
