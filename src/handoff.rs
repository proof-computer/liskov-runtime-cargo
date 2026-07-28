use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use thiserror::Error;

use crate::contact::ContactError;

pub trait CommandExecutor {
    fn exec(&self, command: &[OsString]) -> io::Result<()>;
}

#[derive(Debug, Default)]
pub struct ExecCommand;

impl CommandExecutor for ExecCommand {
    fn exec(&self, command: &[OsString]) -> io::Result<()> {
        let error = Command::new(&command[0]).args(&command[1..]).exec();
        Err(error)
    }
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("runtime contact failed")]
    Contact(#[from] ContactError),
    #[error("customer command could not be executed")]
    Exec(#[source] io::Error),
}

pub fn contact_then_exec<F>(
    contact: F,
    executor: &dyn CommandExecutor,
    command: &[OsString],
) -> Result<(), RunError>
where
    F: FnOnce() -> Result<(), ContactError>,
{
    contact()?;
    executor.exec(command).map_err(RunError::Exec)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct RecordingExecutor {
        calls: Mutex<Vec<Vec<OsString>>>,
    }

    impl RecordingExecutor {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandExecutor for RecordingExecutor {
        fn exec(&self, command: &[OsString]) -> io::Result<()> {
            self.calls.lock().unwrap().push(command.to_vec());
            Ok(())
        }
    }

    #[test]
    fn contact_failure_never_invokes_the_customer_command() {
        let executor = RecordingExecutor::new();
        let error = contact_then_exec(
            || Err(ContactError::PermanentServerRejection),
            &executor,
            &[OsString::from("customer"), OsString::from("--arg")],
        )
        .unwrap_err();
        assert!(matches!(error, RunError::Contact(_)));
        assert!(executor.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn successful_contact_preserves_exact_command_argv() {
        let executor = RecordingExecutor::new();
        let expected = vec![
            OsString::from("/opt/customer app"),
            OsString::from("--literal"),
            OsString::from("value with spaces"),
            OsString::from("$not-expanded"),
        ];
        contact_then_exec(|| Ok(()), &executor, &expected).unwrap();
        assert_eq!(*executor.calls.lock().unwrap(), vec![expected]);
    }
}
