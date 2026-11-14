//! rex-projects runs cooperating coding Agents on many Projects at once
//! inside Rex. See `docs/adr/` for the design.

pub mod cli;
pub mod config;
pub mod domain;
pub mod hook;
pub mod mcp;
pub mod paths;
pub mod provider;
pub mod rex;
pub mod serve;
pub mod store;
pub mod worktree;
