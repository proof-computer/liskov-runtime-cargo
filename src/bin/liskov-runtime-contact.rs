use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;
use liskov_runtime_cargo::{
    DEFAULT_CORE_URL, ExecCommand, RunError, contact_then_exec, establish_runtime_contact,
};

#[derive(Debug, Parser)]
#[command(
    name = "liskov-runtime-contact",
    version,
    about = "Establish signed Liskov runtime contact, then exec the customer command"
)]
struct Cli {
    /// Liskov core base URL
    #[arg(long, value_name = "URL")]
    core_url: Option<String>,

    /// Customer command and arguments; must follow `--`
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<OsString>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let core_url = cli
        .core_url
        .or_else(|| std::env::var("LISKOV_CORE_URL").ok())
        .unwrap_or_else(|| DEFAULT_CORE_URL.to_owned());
    let bridge_socket = match std::env::var("BRIDGE_SOCKET") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("liskov-runtime-contact: BRIDGE_SOCKET is required");
            return ExitCode::from(2);
        }
    };

    match contact_then_exec(
        || {
            establish_runtime_contact(&core_url, &bridge_socket)?;
            Ok(())
        },
        &ExecCommand,
        &cli.command,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Contact(error)) => {
            eprintln!("liskov-runtime-contact: {error}");
            ExitCode::from(error.exit_category() as u8)
        }
        Err(RunError::Exec(_)) => {
            eprintln!("liskov-runtime-contact: customer command could not be executed");
            ExitCode::from(126)
        }
    }
}
