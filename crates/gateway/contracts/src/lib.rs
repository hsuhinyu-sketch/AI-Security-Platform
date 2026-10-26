//! Shared gateway lifecycle contracts, independent of protocols and the runtime host.
//!
//! Identity and authorization models remain owned by the existing security crates.
//! Only contracts with actual cross-component consumers belong here.

pub mod revision;

pub use revision::{ConfigLease, ConfigRevision};

#[cfg(test)]
mod tests;
