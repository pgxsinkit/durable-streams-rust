//! Process-local retirement coordination primitives.
//!
//! This first slice deliberately contains no executor or request-path wiring.
//! The physical worker pool and asynchronous coordinator land as separate,
//! reviewable modules after this completion/admission foundation.

mod foundation;

pub(crate) use foundation::*;
