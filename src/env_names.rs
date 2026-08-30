//! Canonical names of the Liskov-owned runtime environment contract.
//!
//! Liskov-owned variables are migrating to the `LISKOV_*` prefix the workspace
//! constitution requires (`BKLG-20260829-m8kd`). Step 1 is reader-side only:
//! every reader prefers the `LISKOV_*` name and falls back to the legacy one.
//! The platform still emits only the legacy names, so the alias is a no-op
//! until the emitter flips.
//!
//! `BRIDGE_SOCKET` is deliberately absent from this module. It is supplied by
//! the Acurast Cargo runtime, it is not Liskov-owned, and it must never be
//! renamed or aliased.

/// The signed runtime-bootstrap envelope handed to the helper through the
/// on-chain `acurast.setEnvironments` handoff. It carries a bearer diagnostic
/// token, so it is reserved against signed runtime-environment override and
/// removed from the customer environment before startup.
pub const BOOTSTRAP_ENV: &str = "LISKOV_BOOTSTRAP";

/// Migration bridge for [`BOOTSTRAP_ENV`]; still the only name the platform
/// emits today.
pub const LEGACY_BOOTSTRAP_ENV: &str = "PROOF_SLIPWAY_BOOTSTRAP";

/// Reader preference order for the signed runtime-bootstrap envelope.
pub const BOOTSTRAP_ENV_NAMES: &[&str] = &[BOOTSTRAP_ENV, LEGACY_BOOTSTRAP_ENV];

/// The job-bound Lockbox bootstrap metadata the supervisor uses to resolve the
/// server-owned Blackbox log configuration.
pub const LOCKBOX_BOOTSTRAP_ENV: &str = "LISKOV_LOCKBOX_BOOTSTRAP";

/// Migration bridge for [`LOCKBOX_BOOTSTRAP_ENV`].
pub const LEGACY_LOCKBOX_BOOTSTRAP_ENV: &str = "PROOF_LOCKBOX_BOOTSTRAP";

/// Reader preference order for the job-bound Lockbox bootstrap metadata.
pub const LOCKBOX_BOOTSTRAP_ENV_NAMES: &[&str] =
    &[LOCKBOX_BOOTSTRAP_ENV, LEGACY_LOCKBOX_BOOTSTRAP_ENV];

/// Internal fail-closed supervision canary control. Not a customer-authored
/// policy surface.
pub const SUPERVISION_CANARY_ENV: &str = "LISKOV_CARGO_SUPERVISION_CANARY_JSON";

/// Exact-job Runtime SSH connector credential taken out of the authenticated
/// bootstrap response before customer startup.
pub const RUNTIME_SSH_CREDENTIAL_ENV: &str = "LISKOV_RUNTIME_SSH_CREDENTIAL_V1";

/// Names a signed runtime-environment response may never set, and which are
/// removed from the inherited customer environment before startup.
///
/// One list serves both roles on purpose. The rename hazard this module exists
/// for is a name that is read under its new spelling but reserved or redacted
/// only under its old one; with a single list that state is unrepresentable.
///
/// The Lockbox bootstrap names are deliberately **absent**. They carry only the
/// metadata telling a job how to fetch a secret — never a secret — the customer
/// workload is expected to see them, and `hydrate_blackbox_log_config` accepts
/// them from the signed runtime-environment response, which reserving them
/// would sever.
pub const PROTECTED_ENV_NAMES: &[&str] = &[
    BOOTSTRAP_ENV,
    LEGACY_BOOTSTRAP_ENV,
    SUPERVISION_CANARY_ENV,
    RUNTIME_SSH_CREDENTIAL_ENV,
];

/// First value present under `names`, in order, from `lookup`.
///
/// Presence, not non-emptiness, decides: an explicitly empty value under the
/// preferred name keeps its existing meaning rather than silently falling
/// through to the legacy name.
pub fn first_present<F>(names: &[&str], lookup: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    names.iter().find_map(|name| lookup(name))
}

/// [`first_present`] against this process's environment.
pub fn first_present_in_process_env(names: &[&str]) -> Option<String> {
    first_present(names, |name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn bootstrap_reader_prefers_the_liskov_name_and_falls_back_to_the_legacy_one() {
        assert_eq!(
            first_present(
                BOOTSTRAP_ENV_NAMES,
                lookup(&[(BOOTSTRAP_ENV, "new"), (LEGACY_BOOTSTRAP_ENV, "old")])
            ),
            Some("new".to_owned())
        );
        assert_eq!(
            first_present(
                BOOTSTRAP_ENV_NAMES,
                lookup(&[(LEGACY_BOOTSTRAP_ENV, "old")])
            ),
            Some("old".to_owned())
        );
        assert_eq!(
            first_present(BOOTSTRAP_ENV_NAMES, lookup(&[(BOOTSTRAP_ENV, "new")])),
            Some("new".to_owned())
        );
        assert_eq!(first_present(BOOTSTRAP_ENV_NAMES, lookup(&[])), None);
    }

    #[test]
    fn an_explicitly_empty_preferred_value_does_not_fall_through() {
        assert_eq!(
            first_present(
                BOOTSTRAP_ENV_NAMES,
                lookup(&[(BOOTSTRAP_ENV, ""), (LEGACY_BOOTSTRAP_ENV, "old")])
            ),
            Some(String::new())
        );
    }

    #[test]
    fn lockbox_reader_prefers_the_liskov_name_and_falls_back_to_the_legacy_one() {
        assert_eq!(
            first_present(
                LOCKBOX_BOOTSTRAP_ENV_NAMES,
                lookup(&[
                    (LOCKBOX_BOOTSTRAP_ENV, "new"),
                    (LEGACY_LOCKBOX_BOOTSTRAP_ENV, "old"),
                ])
            ),
            Some("new".to_owned())
        );
        assert_eq!(
            first_present(
                LOCKBOX_BOOTSTRAP_ENV_NAMES,
                lookup(&[(LEGACY_LOCKBOX_BOOTSTRAP_ENV, "old")])
            ),
            Some("old".to_owned())
        );
    }

    #[test]
    fn both_bootstrap_spellings_are_reserved_and_redacted() {
        for name in BOOTSTRAP_ENV_NAMES {
            assert!(
                PROTECTED_ENV_NAMES.contains(name),
                "{name} must be reserved against signed runtime-env override \
                 and removed from the customer environment"
            );
        }
        assert!(PROTECTED_ENV_NAMES.contains(&SUPERVISION_CANARY_ENV));
        assert!(PROTECTED_ENV_NAMES.contains(&RUNTIME_SSH_CREDENTIAL_ENV));
    }

    #[test]
    fn neither_lockbox_spelling_is_reserved() {
        // Reserving these would sever the signed runtime-environment delivery
        // channel `hydrate_blackbox_log_config` reads, and would hide the
        // metadata from customer workloads that legitimately see it today.
        for name in LOCKBOX_BOOTSTRAP_ENV_NAMES {
            assert!(
                !PROTECTED_ENV_NAMES.contains(name),
                "{name} carries no secret and must stay deliverable and visible"
            );
        }
    }

    #[test]
    fn bridge_socket_is_never_aliased_or_reserved() {
        // BRIDGE_SOCKET belongs to the Acurast Cargo runtime, not to Liskov.
        for name in BOOTSTRAP_ENV_NAMES
            .iter()
            .chain(LOCKBOX_BOOTSTRAP_ENV_NAMES)
            .chain(PROTECTED_ENV_NAMES)
        {
            assert_ne!(*name, "BRIDGE_SOCKET");
        }
    }

    #[test]
    fn every_protected_name_is_liskov_owned() {
        for name in PROTECTED_ENV_NAMES {
            assert!(
                name.starts_with("LISKOV_") || name.starts_with("PROOF_"),
                "{name} is not a Liskov-owned name"
            );
        }
    }
}
