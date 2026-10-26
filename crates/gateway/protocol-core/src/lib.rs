//! Protocol-independent lifecycle and wire framing shared by gateway adapters.
pub mod execution;
pub mod model;
pub mod revision;
pub mod sse;

#[cfg(test)]
mod tests;
