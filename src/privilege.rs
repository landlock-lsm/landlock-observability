// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit management of the calling thread's collection privileges.
//!
//! Linux credentials and capability changes are per-thread. Call
//! [`Privileges::minimize()`] near process entry, before creating any other
//! thread, and do
//! not create threads until collector preparation has completed. The runtime
//! rechecks this serialized single-threaded contract at each security
//! transition; it does not attempt to update arbitrary threads. If scoped
//! cleanup cannot verify that retained setup authority was removed, the
//! process aborts instead of continuing with an uncertain credential state.

use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;

use rustix::io::Errno;
use rustix::thread::{
    capabilities, capability_is_in_ambient_set, capability_is_in_bounding_set,
    clear_ambient_capability_set, no_new_privs, remove_capability_from_bounding_set,
    set_capabilities, set_no_new_privs, CapabilitySet, CapabilitySets,
};

const SETUP_CAPABILITIES: CapabilitySet = CapabilitySet::BPF.union(CapabilitySet::PERFMON);
// rustix represents Linux capability sets as a u64, which is also the widest
// set this implementation can inspect and clear.
const KNOWN_CAPABILITY_BITS: u32 = u64::BITS;

/// The reason privilege management failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivilegeErrorKind {
    /// More than one thread exists, or the thread count changed at a security boundary.
    NotSingleThreaded,
    /// Required BPF setup or capability-reduction authority is unavailable.
    MissingSetupCapability,
    /// A minimized privilege value cannot be reused after final capability
    /// removal.
    AlreadyFinalized,
    /// The current credential state could not be inspected.
    Inspect,
    /// A credential transition failed.
    Transition,
    /// The credential state after a transition could not be verified.
    Verify,
}

/// A failure to minimize or finish using collection privileges.
#[derive(Debug)]
#[non_exhaustive]
pub struct PrivilegeError {
    kind: PrivilegeErrorKind,
    detail: PrivilegeErrorDetail,
}

#[derive(Debug)]
enum PrivilegeErrorDetail {
    Message(&'static str),
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Errno {
        operation: &'static str,
        source: Errno,
    },
}

impl PrivilegeError {
    fn message(kind: PrivilegeErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            detail: PrivilegeErrorDetail::Message(message),
        }
    }

    fn io(kind: PrivilegeErrorKind, operation: &'static str, source: std::io::Error) -> Self {
        Self {
            kind,
            detail: PrivilegeErrorDetail::Io { operation, source },
        }
    }

    fn errno(kind: PrivilegeErrorKind, operation: &'static str, source: Errno) -> Self {
        Self {
            kind,
            detail: PrivilegeErrorDetail::Errno { operation, source },
        }
    }

    /// Returns the stage at which privilege handling failed.
    pub const fn kind(&self) -> PrivilegeErrorKind {
        self.kind
    }
}

impl fmt::Display for PrivilegeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "failed to manage collector privileges: ")?;
        match &self.detail {
            PrivilegeErrorDetail::Message(message) => formatter.write_str(message),
            PrivilegeErrorDetail::Io { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
            PrivilegeErrorDetail::Errno { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
        }
    }
}

impl Error for PrivilegeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.detail {
            PrivilegeErrorDetail::Message(_) => None,
            PrivilegeErrorDetail::Io { source, .. } => Some(source),
            PrivilegeErrorDetail::Errno { source, .. } => Some(source),
        }
    }
}

fn inspect_io(operation: &'static str, error: std::io::Error) -> PrivilegeError {
    PrivilegeError::io(PrivilegeErrorKind::Inspect, operation, error)
}

fn inspect_errno(operation: &'static str, error: Errno) -> PrivilegeError {
    PrivilegeError::errno(PrivilegeErrorKind::Inspect, operation, error)
}

fn transition_errno(operation: &'static str, error: Errno) -> PrivilegeError {
    PrivilegeError::errno(PrivilegeErrorKind::Transition, operation, error)
}

fn check_single_threaded() -> Result<(), PrivilegeError> {
    let mut tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|error| inspect_io("read /proc/self/task", error))?;
    let first = tasks
        .next()
        .transpose()
        .map_err(|error| inspect_io("read /proc/self/task", error))?;
    let second = tasks
        .next()
        .transpose()
        .map_err(|error| inspect_io("read /proc/self/task", error))?;
    if first.is_some() && second.is_none() {
        Ok(())
    } else {
        Err(PrivilegeError::message(
            PrivilegeErrorKind::NotSingleThreaded,
            "the process is not single-threaded",
        ))
    }
}

fn current_capabilities() -> Result<CapabilitySets, PrivilegeError> {
    capabilities(None).map_err(|error| inspect_errno("read capability sets", error))
}

fn change_capabilities(sets: CapabilitySets) -> Result<(), PrivilegeError> {
    set_capabilities(None, sets).map_err(|error| transition_errno("set capability sets", error))
}

fn current_no_new_privs() -> Result<bool, PrivilegeError> {
    no_new_privs().map_err(|error| inspect_errno("read no_new_privs", error))
}

fn enable_no_new_privs() -> Result<(), PrivilegeError> {
    set_no_new_privs(true).map_err(|error| transition_errno("set no_new_privs", error))
}

fn clear_ambient() -> Result<(), PrivilegeError> {
    clear_ambient_capability_set()
        .map_err(|error| transition_errno("clear ambient capabilities", error))
}

fn ambient_contains(capability: CapabilitySet) -> Result<bool, PrivilegeError> {
    capability_is_in_ambient_set(capability)
        .map_err(|error| inspect_errno("read ambient capability set", error))
}

fn bounding_contains(capability: CapabilitySet) -> Result<Option<bool>, PrivilegeError> {
    match capability_is_in_bounding_set(capability) {
        Ok(value) => Ok(Some(value)),
        Err(Errno::INVAL) => Ok(None),
        Err(error) => Err(inspect_errno("read capability bounding set", error)),
    }
}

fn remove_bounding(capability: CapabilitySet) -> Result<(), PrivilegeError> {
    remove_capability_from_bounding_set(capability)
        .map_err(|error| transition_errno("reduce capability bounding set", error))
}

fn clear_bounding() -> Result<(), PrivilegeError> {
    each_supported_capability(|capability| {
        if bounding_contains(capability)? == Some(true) {
            remove_bounding(capability)?;
        }
        Ok(())
    })
}

fn capability(index: u32) -> Option<CapabilitySet> {
    1_u64
        .checked_shl(index)
        .map(CapabilitySet::from_bits_retain)
}

fn each_supported_capability(
    mut action: impl FnMut(CapabilitySet) -> Result<(), PrivilegeError>,
) -> Result<(), PrivilegeError> {
    for capability in (0..KNOWN_CAPABILITY_BITS).map_while(capability) {
        if bounding_contains(capability)?.is_none() {
            break;
        }
        action(capability)?;
    }
    Ok(())
}

fn verify(expected: CapabilitySets) -> Result<(), PrivilegeError> {
    if !current_no_new_privs()? {
        return Err(PrivilegeError::message(
            PrivilegeErrorKind::Verify,
            "no_new_privs is not set",
        ));
    }
    if current_capabilities()? != expected {
        return Err(PrivilegeError::message(
            PrivilegeErrorKind::Verify,
            "capability sets differ from the requested state",
        ));
    }
    each_supported_capability(|capability| {
        if ambient_contains(capability)? {
            return Err(PrivilegeError::message(
                PrivilegeErrorKind::Verify,
                "the ambient capability set is not empty",
            ));
        }
        if bounding_contains(capability)? == Some(true) {
            return Err(PrivilegeError::message(
                PrivilegeErrorKind::Verify,
                "the capability bounding set is not empty",
            ));
        }
        Ok(())
    })
}

enum Policy {
    Minimized,
    Preserved,
    VerificationPending,
    Finished,
}

#[derive(Clone, Copy)]
enum FinalizationMode {
    Explicit,
    Cleanup,
}

trait FinalizationOps {
    fn check_thread(&mut self) -> Result<(), PrivilegeError>;
    fn clear_ambient(&mut self) -> Result<(), PrivilegeError>;
    fn clear_bounding(&mut self) -> Result<(), PrivilegeError>;
    fn clear_capabilities(&mut self) -> Result<(), PrivilegeError>;
    fn verify(&mut self) -> Result<(), PrivilegeError>;
}

struct ProductionFinalizationOps;

impl FinalizationOps for ProductionFinalizationOps {
    fn check_thread(&mut self) -> Result<(), PrivilegeError> {
        check_single_threaded()
    }

    fn clear_ambient(&mut self) -> Result<(), PrivilegeError> {
        clear_ambient()
    }

    fn clear_bounding(&mut self) -> Result<(), PrivilegeError> {
        clear_bounding()
    }

    fn clear_capabilities(&mut self) -> Result<(), PrivilegeError> {
        change_capabilities(empty_capabilities())
    }

    fn verify(&mut self) -> Result<(), PrivilegeError> {
        verify(empty_capabilities())
    }
}

fn empty_capabilities() -> CapabilitySets {
    CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    }
}

/// A non-transferable privilege policy scoped to collector preparation.
///
/// A minimized value is reusable after BPF setup or finalization failures that
/// happen before the final capability sets are removed. Once that removal
/// succeeds, the value is not reusable, even if verification fails. Dropping
/// it retries only that verification and aborts if the empty credential state
/// still cannot be verified.
///
/// Unless successful collector preparation already finalized it, dropping a
/// value returned by [`Privileges::minimize()`] removes and verifies all
/// remaining setup capabilities. Failure to establish the final state aborts
/// the process rather than allowing execution with unverifiable authority.
#[must_use = "the privilege policy must be passed to collector preparation"]
#[non_exhaustive]
pub struct Privileges {
    policy: Policy,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl Privileges {
    /// Minimizes the calling thread's privileges for collector setup.
    ///
    /// This must be called while the process is single-threaded. Before
    /// changing credentials it verifies that the calling thread has `CAP_BPF`,
    /// `CAP_PERFMON`, and enough authority to empty a nonempty bounding set. It
    /// then sets `no_new_privs`, clears ambient and bounding capabilities, and
    /// retains only `CAP_BPF` and `CAP_PERFMON` in the effective and permitted
    /// sets. The returned value is neither `Send` nor `Sync`.
    ///
    /// Pass it to [`crate::collector::CollectorConfig::prepare()`].
    #[must_use = "the minimized privileges must be passed to collector preparation"]
    pub fn minimize() -> Result<Self, PrivilegeError> {
        preflight_minimization()?;
        check_single_threaded()?;
        enable_no_new_privs()?;
        let mut cleanup = MinimizationCleanup { armed: true };
        check_single_threaded()?;
        clear_ambient()?;
        check_single_threaded()?;
        clear_bounding()?;
        check_single_threaded()?;
        let setup = CapabilitySets {
            effective: SETUP_CAPABILITIES,
            permitted: SETUP_CAPABILITIES,
            inheritable: CapabilitySet::empty(),
        };
        change_capabilities(setup)?;
        verify(setup)?;
        cleanup.armed = false;
        Ok(Self {
            policy: Policy::Minimized,
            not_send_or_sync: PhantomData,
        })
    }

    /// Leaves credential policy under explicit external management.
    ///
    /// Passing this value to collector preparation performs no credential
    /// mutation or verification.
    #[must_use = "the preserved policy must be passed to collector preparation"]
    pub fn preserve() -> Self {
        Self {
            policy: Policy::Preserved,
            not_send_or_sync: PhantomData,
        }
    }

    pub(crate) fn ensure_can_prepare(&self) -> Result<(), PrivilegeError> {
        if matches!(self.policy, Policy::VerificationPending | Policy::Finished) {
            return Err(already_finalized());
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), PrivilegeError> {
        let mut ops = ProductionFinalizationOps;
        finish_policy_with(&mut self.policy, FinalizationMode::Explicit, &mut ops)
    }
}

impl Drop for Privileges {
    fn drop(&mut self) {
        let mut ops = ProductionFinalizationOps;
        if finish_policy_with(&mut self.policy, FinalizationMode::Cleanup, &mut ops).is_err() {
            std::process::abort();
        }
    }
}

fn preflight_minimization() -> Result<(), PrivilegeError> {
    check_single_threaded()?;
    let current = current_capabilities()?;
    if !current.permitted.contains(SETUP_CAPABILITIES) {
        return Err(PrivilegeError::message(
            PrivilegeErrorKind::MissingSetupCapability,
            "CAP_BPF and CAP_PERFMON must be permitted",
        ));
    }
    let mut bounding_nonempty = false;
    each_supported_capability(|capability| {
        bounding_nonempty |= bounding_contains(capability)? == Some(true);
        Ok(())
    })?;
    if bounding_nonempty && !current.effective.contains(CapabilitySet::SETPCAP) {
        return Err(PrivilegeError::message(
            PrivilegeErrorKind::MissingSetupCapability,
            "CAP_SETPCAP is required to empty the capability bounding set",
        ));
    }
    Ok(())
}

struct MinimizationCleanup {
    armed: bool,
}

impl Drop for MinimizationCleanup {
    fn drop(&mut self) {
        if self.armed {
            let mut policy = Policy::Minimized;
            let mut ops = ProductionFinalizationOps;
            if finish_policy_with(&mut policy, FinalizationMode::Cleanup, &mut ops).is_err() {
                std::process::abort();
            }
        }
    }
}

fn already_finalized() -> PrivilegeError {
    PrivilegeError::message(
        PrivilegeErrorKind::AlreadyFinalized,
        "minimized privileges cannot be reused after final capability removal",
    )
}

fn finish_policy_with<O: FinalizationOps>(
    policy: &mut Policy,
    mode: FinalizationMode,
    ops: &mut O,
) -> Result<(), PrivilegeError> {
    match policy {
        Policy::Preserved | Policy::Finished => return Ok(()),
        Policy::VerificationPending => {
            if matches!(mode, FinalizationMode::Explicit) {
                return Err(already_finalized());
            }
            ops.verify()?;
            *policy = Policy::Finished;
            return Ok(());
        }
        Policy::Minimized => {}
    }

    ops.check_thread()?;
    ops.clear_ambient()?;
    ops.check_thread()?;
    ops.clear_bounding()?;
    ops.check_thread()?;
    ops.clear_capabilities()?;
    *policy = Policy::VerificationPending;
    ops.verify()?;
    *policy = Policy::Finished;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bit_shifts_are_checked() {
        assert!(capability(KNOWN_CAPABILITY_BITS.saturating_sub(1)).is_some());
        assert!(capability(KNOWN_CAPABILITY_BITS).is_none());
        assert!(capability(u32::MAX).is_none());
    }

    #[test]
    fn detects_an_additional_thread() {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let thread = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();
        let error = check_single_threaded().unwrap_err();
        assert_eq!(error.kind(), PrivilegeErrorKind::NotSingleThreaded);
        release_tx.send(()).unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn syscall_errors_retain_their_source() {
        let error = transition_errno("fake transition", Errno::PERM);
        assert_eq!(
            error.source().expect("errno source is present").to_string(),
            Errno::PERM.to_string()
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FinalizationOperation {
        CheckThread,
        ClearAmbient,
        ClearBounding,
        ClearCapabilities,
        Verify,
    }

    struct FakeFinalizationOps {
        operations: Vec<FinalizationOperation>,
        fail_at: Option<usize>,
    }

    impl FakeFinalizationOps {
        fn new(fail_at: Option<usize>) -> Self {
            Self {
                operations: Vec::new(),
                fail_at,
            }
        }

        fn perform(&mut self, operation: FinalizationOperation) -> Result<(), PrivilegeError> {
            self.operations.push(operation);
            if self.fail_at == Some(self.operations.len() - 1) {
                Err(PrivilegeError::message(
                    PrivilegeErrorKind::Transition,
                    "injected finalization failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    impl FinalizationOps for FakeFinalizationOps {
        fn check_thread(&mut self) -> Result<(), PrivilegeError> {
            self.perform(FinalizationOperation::CheckThread)
        }

        fn clear_ambient(&mut self) -> Result<(), PrivilegeError> {
            self.perform(FinalizationOperation::ClearAmbient)
        }

        fn clear_bounding(&mut self) -> Result<(), PrivilegeError> {
            self.perform(FinalizationOperation::ClearBounding)
        }

        fn clear_capabilities(&mut self) -> Result<(), PrivilegeError> {
            self.perform(FinalizationOperation::ClearCapabilities)
        }

        fn verify(&mut self) -> Result<(), PrivilegeError> {
            self.perform(FinalizationOperation::Verify)
        }
    }

    const FINALIZATION_OPERATIONS: [FinalizationOperation; 7] = [
        FinalizationOperation::CheckThread,
        FinalizationOperation::ClearAmbient,
        FinalizationOperation::CheckThread,
        FinalizationOperation::ClearBounding,
        FinalizationOperation::CheckThread,
        FinalizationOperation::ClearCapabilities,
        FinalizationOperation::Verify,
    ];

    #[test]
    fn finalization_uses_the_required_order() {
        let mut policy = Policy::Minimized;
        let mut ops = FakeFinalizationOps::new(None);
        finish_policy_with(&mut policy, FinalizationMode::Explicit, &mut ops).unwrap();
        assert_eq!(ops.operations, FINALIZATION_OPERATIONS);
        assert!(matches!(policy, Policy::Finished));
    }

    #[test]
    fn failures_through_capability_removal_remain_retryable() {
        for fail_at in 0..6 {
            let mut policy = Policy::Minimized;
            let mut ops = FakeFinalizationOps::new(Some(fail_at));
            finish_policy_with(&mut policy, FinalizationMode::Explicit, &mut ops).unwrap_err();
            assert_eq!(ops.operations, FINALIZATION_OPERATIONS[..=fail_at]);
            assert!(matches!(policy, Policy::Minimized));
        }
    }

    #[test]
    fn verification_failure_is_not_retryable_by_preparation() {
        let mut policy = Policy::Minimized;
        let mut ops = FakeFinalizationOps::new(Some(6));
        finish_policy_with(&mut policy, FinalizationMode::Explicit, &mut ops).unwrap_err();
        assert_eq!(ops.operations, FINALIZATION_OPERATIONS);
        assert!(matches!(policy, Policy::VerificationPending));
    }

    #[test]
    fn non_reusable_privileges_reject_another_preparation() {
        for policy in [Policy::VerificationPending, Policy::Finished] {
            let mut privileges = Privileges {
                policy,
                not_send_or_sync: PhantomData,
            };
            let error = privileges.ensure_can_prepare().unwrap_err();
            assert_eq!(error.kind(), PrivilegeErrorKind::AlreadyFinalized);
            assert_eq!(
                error.to_string(),
                "failed to manage collector privileges: minimized privileges cannot be reused after final capability removal"
            );
            privileges.policy = Policy::Preserved;
        }
    }

    #[test]
    fn explicit_pending_finalization_does_not_retry_verification() {
        let mut policy = Policy::VerificationPending;
        let mut ops = FakeFinalizationOps::new(None);
        let error =
            finish_policy_with(&mut policy, FinalizationMode::Explicit, &mut ops).unwrap_err();
        assert_eq!(error.kind(), PrivilegeErrorKind::AlreadyFinalized);
        assert!(ops.operations.is_empty());
        assert!(matches!(policy, Policy::VerificationPending));
    }

    #[test]
    fn cleanup_pending_retries_only_verification() {
        let mut policy = Policy::VerificationPending;
        let mut ops = FakeFinalizationOps::new(None);
        finish_policy_with(&mut policy, FinalizationMode::Cleanup, &mut ops).unwrap();
        assert_eq!(ops.operations, [FinalizationOperation::Verify]);
        assert!(matches!(policy, Policy::Finished));

        let mut policy = Policy::VerificationPending;
        let mut ops = FakeFinalizationOps::new(Some(0));
        finish_policy_with(&mut policy, FinalizationMode::Cleanup, &mut ops).unwrap_err();
        assert_eq!(ops.operations, [FinalizationOperation::Verify]);
        assert!(matches!(policy, Policy::VerificationPending));
    }

    #[test]
    fn preserve_does_not_change_credentials() {
        let before_capabilities = current_capabilities().unwrap();
        let before_no_new_privs = current_no_new_privs().unwrap();
        let before_sets = supported_external_sets().unwrap();
        drop(Privileges::preserve());
        assert_eq!(current_capabilities().unwrap(), before_capabilities);
        assert_eq!(current_no_new_privs().unwrap(), before_no_new_privs);
        assert_eq!(supported_external_sets().unwrap(), before_sets);
    }

    fn supported_external_sets() -> Result<Vec<(bool, bool)>, PrivilegeError> {
        let mut sets = Vec::new();
        each_supported_capability(|capability| {
            sets.push((
                ambient_contains(capability)?,
                bounding_contains(capability)?.unwrap_or(false),
            ));
            Ok(())
        })?;
        Ok(sets)
    }
}
