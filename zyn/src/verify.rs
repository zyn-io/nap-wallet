//! Authorization is consensus code and lives in `zyn-vm` so a sequencer,
//! replica, and proof guest execute the same verifier. This module preserves
//! the original public path for applications built against `zyn`.

pub use zyn_vm::verify::*;
