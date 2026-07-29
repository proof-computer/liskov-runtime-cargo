//! Native first contact for Liskov-managed Acurast Cargo/PRoot workloads.

pub mod bridge;
pub mod contact;
pub mod handoff;
pub mod http;
pub mod precontact;
pub mod probe;
pub mod protocol;

pub use contact::{
    ContactError, ContactRuntime, DEFAULT_CORE_URL, ExitCategory, RetryPolicy,
    establish_runtime_contact, establish_runtime_contact_with,
};
pub use handoff::{CommandExecutor, ExecCommand, RunError, contact_then_exec};
