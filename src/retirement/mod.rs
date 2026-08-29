//! Process-local retirement coordination primitives.
//!
//! This first slice deliberately contains no executor or request-path wiring.
//! The physical worker pool and asynchronous coordinator land as separate,
//! reviewable modules after this completion/admission foundation.

mod coordinator;
mod foundation;
mod physical;

#[allow(unused_imports)] // TODO(retirement-005): handler wiring consumes this export.
pub(crate) use coordinator::*;
pub(crate) use foundation::*;
pub(crate) use physical::*;
