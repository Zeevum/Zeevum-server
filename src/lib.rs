//! Zeevum server
//!
//! The binary in `src/main.rs` is a thin wrapper around [`server::serve`]
//! Everything else lives here so that integration tests can start a real
//! server on an ephemeral port with their own database and certificates

#[macro_use]
pub mod logger;

pub mod config;
pub mod connection;
pub mod db;
pub mod frames;
pub mod handlers;
pub mod handshake;
pub mod hub;
pub mod ratelimit;
pub mod server;
pub mod tls;

pub use config::Config;
pub use server::{AppContext, serve};
