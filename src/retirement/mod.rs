//! Process-local retirement coordination primitives.
//!
//! This first slice deliberately contains no executor or request-path wiring.
//! The physical worker pool and asynchronous coordinator land as separate,
//! reviewable modules after this completion/admission foundation.

mod foundation;
mod physical;

pub(crate) use foundation::*;
#[allow(unused_imports)] // TODO(retirement-C): coordinator consumes this export.
pub(crate) use physical::*;
