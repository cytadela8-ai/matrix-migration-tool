//! Matrix account migration. SDK encryption and live REST state have distinct responsibilities:
//! SDK stores keys and decrypts; REST reads state immediately before convergent writes.

#![recursion_limit = "256"]

pub mod api;
pub mod config;
pub mod crypto;
pub mod history;
pub mod migration;
pub mod policy;
pub mod report;
pub mod session;
pub mod verification;
