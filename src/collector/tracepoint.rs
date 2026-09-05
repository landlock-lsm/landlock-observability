// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ffi::OsStr;

use libbpf_rs::btf::types::Typedef;
use libbpf_rs::btf::Btf;
use libbpf_rs::{Error, ErrorKind};

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

// Keep each Landlock tracing-interface generation as an independent,
// immutable compatibility unit.  A future generation must have its own
// descriptor and program set, select the newest complete supported generation,
// and preserve every older complete generation as a fallback where possible.
// Consumers must continue to use typed event availability rather than branch
// directly on kernel generation numbers.
const GENERATION_1_TARGETS: [&[u8]; 12] = [
    b"btf_trace_landlock_create_ruleset",
    b"btf_trace_landlock_add_rule_fs",
    b"btf_trace_landlock_add_rule_net",
    b"btf_trace_landlock_create_domain",
    b"btf_trace_landlock_enforce_domain",
    b"btf_trace_landlock_deny_access_fs",
    b"btf_trace_landlock_deny_access_net",
    b"btf_trace_landlock_deny_ptrace",
    b"btf_trace_landlock_deny_scope_signal",
    b"btf_trace_landlock_deny_scope_abstract_unix_socket",
    b"btf_trace_landlock_free_domain",
    b"btf_trace_landlock_free_ruleset",
];
const GENERATION_1_COMPLETE: u16 = (1 << GENERATION_1_TARGETS.len()) - 1;

pub(super) fn generation_1_is_missing(load_error: &Error) -> bool {
    generation_1_is_missing_with(load_error, generation_1_target_mask)
}

fn generation_1_is_missing_with(
    load_error: &Error,
    target_mask: impl FnOnce() -> Result<u16, Error>,
) -> bool {
    should_diagnose(load_error.kind())
        && target_mask().is_ok_and(|mask| mask != GENERATION_1_COMPLETE)
}

fn should_diagnose(kind: ErrorKind) -> bool {
    // libbpf reports a missing tp_btf target as ESRCH.  std::io classifies it
    // as Uncategorized, which libbpf-rs folds into Other.  NotFound covers
    // equivalent lookup failures from related libbpf paths.  Other is broader
    // than ESRCH, so reclassification still requires canonical BTF to
    // conclusively lack a required target and retains this load error as the
    // source.  Permission, verifier, and unsupported-operation failures have
    // distinct classifications and are never diagnosed here.
    matches!(kind, ErrorKind::NotFound | ErrorKind::Other)
}

fn generation_1_target_mask() -> Result<u16, Error> {
    // Parse only the canonical raw-BTF file: unlike libbpf's vmlinux loader,
    // this cannot search fallback ELF images.
    let btf = Btf::from_path(VMLINUX_BTF)?;
    let mut mask = 0;
    for typedef in btf.type_by_kind::<Typedef<'_>>() {
        if let Some(name) = typedef.name() {
            mark_generation_1_target(&mut mask, name);
            if mask == GENERATION_1_COMPLETE {
                break;
            }
        }
    }
    Ok(mask)
}

fn mark_generation_1_target(mask: &mut u16, name: &OsStr) {
    if let Some(index) = GENERATION_1_TARGETS
        .iter()
        .position(|target| name.as_encoded_bytes() == *target)
    {
        *mask |= 1 << index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_1_targets_form_one_complete_bitset() {
        let mut mask = 0;
        for target in GENERATION_1_TARGETS {
            mark_generation_1_target(&mut mask, OsStr::new(std::str::from_utf8(target).unwrap()));
        }
        assert_eq!(mask, GENERATION_1_COMPLETE);

        mark_generation_1_target(
            &mut mask,
            OsStr::new("btf_trace_landlock_future_generation"),
        );
        assert_eq!(mask, GENERATION_1_COMPLETE);
    }

    #[test]
    fn diagnosis_is_limited_to_lookup_shaped_load_errors() {
        assert!(should_diagnose(ErrorKind::NotFound));
        assert!(should_diagnose(ErrorKind::Other));
        assert!(!should_diagnose(ErrorKind::PermissionDenied));
        assert!(!should_diagnose(ErrorKind::InvalidInput));
        assert!(!should_diagnose(ErrorKind::InvalidData));
        assert!(!should_diagnose(ErrorKind::Unsupported));
    }

    #[test]
    fn generation_1_diagnosis_composes_load_and_scan_results() {
        let error = |kind| Error::from(std::io::Error::new(kind, "synthetic error"));

        assert!(generation_1_is_missing_with(
            &error(std::io::ErrorKind::NotFound),
            || Ok(0),
        ));
        assert!(generation_1_is_missing_with(
            &error(std::io::ErrorKind::Other),
            || Ok(GENERATION_1_COMPLETE ^ (1 << 7)),
        ));
        assert!(!generation_1_is_missing_with(
            &error(std::io::ErrorKind::NotFound),
            || Ok(GENERATION_1_COMPLETE),
        ));
        assert!(!generation_1_is_missing_with(
            &error(std::io::ErrorKind::NotFound),
            || Err(error(std::io::ErrorKind::NotFound)),
        ));
        assert!(!generation_1_is_missing_with(
            &error(std::io::ErrorKind::Other),
            || Err(error(std::io::ErrorKind::InvalidData)),
        ));

        let target_scan_invoked = std::cell::Cell::new(false);
        assert!(!generation_1_is_missing_with(
            &error(std::io::ErrorKind::PermissionDenied),
            || {
                target_scan_invoked.set(true);
                Ok(0)
            },
        ));
        assert!(!target_scan_invoked.get());
    }
}
