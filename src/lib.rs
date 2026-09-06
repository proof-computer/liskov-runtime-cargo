//! Native first contact for Liskov-managed Acurast Cargo/PRoot workloads.

pub mod access;
pub mod bridge;
pub mod contact;
pub mod coverage;
pub mod diagnostics;
pub mod env_names;
pub mod file_secrets;
pub mod handoff;
pub mod hardware;
pub mod http;
pub mod job_secrets;
pub mod log_config_secret;
pub mod logging;
pub mod precontact;
pub mod probe;
pub mod processor_facts;
pub mod protocol;
pub mod runtime_env;
pub mod supervisor;
pub mod tunnel_probe;

pub use contact::{
    ContactError, ContactRuntime, DEFAULT_CORE_URL, ExitCategory, RetryPolicy,
    establish_runtime_contact, establish_runtime_contact_with,
};
pub use handoff::{CommandExecutor, ExecCommand, RunError, contact_then_exec};
pub use log_config_secret::{LogConfigSecretError, hydrate_blackbox_log_config};
pub use runtime_env::{RuntimeEnvError, load_runtime_environment};
pub use supervisor::{
    SupervisorExit, supervise, supervise_with_environment,
    supervise_with_environment_access_and_processor_facts, supervise_with_environment_and_access,
};
