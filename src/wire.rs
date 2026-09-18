// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt;

use crate::event::{
    AddRuleNetPortEvent, AddRulePathBeneathEvent, BlockerType, CapturedAbstractUnixSocketName,
    CapturedBytes, CapturedBytesError, CapturedBytesOrigin, CapturedCommand, CreateDomainEvent,
    CreateRulesetEvent, DenialContext, DenyAccessFsEvent, DenyAccessNetEvent, DenyPtraceEvent,
    DenyScopeAbstractUnixSocketEvent, DenyScopeSignalEvent, DomainId, DomainMembership,
    EnforceDomainEvent, Event, FilesystemAccess, FreeDomainEvent, FreeRulesetEvent,
    HierarchySnapshot, KernelTimestamp, LandlockId, LandlockIdKind, NetworkAccess, ProcessId,
    ScopeAccess, ThreadId,
};

const RECORD_SIZE: usize = 352;
const TIMESTAMP_OFFSET: usize = 0;
const TYPE_OFFSET: usize = 8;
const UNION_OFFSET: usize = 16;
const COMM_SIZE: usize = 16;
const PATH_SIZE: usize = 256;
const ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN: usize = 107;

const CREATE_RULESET: u8 = 1;
const ADD_RULE_PATH_BENEATH: u8 = 2;
const ADD_RULE_NET_PORT: u8 = 3;
const CREATE_DOMAIN: u8 = 4;
const DENY_ACCESS_FS: u8 = 5;
const DENY_ACCESS_NET: u8 = 6;
const DENY_PTRACE: u8 = 7;
const DENY_SCOPE_SIGNAL: u8 = 8;
const DENY_SCOPE_ABSTRACT_UNIX_SOCKET: u8 = 9;
const FREE_DOMAIN: u8 = 10;
const FREE_RULESET: u8 = 11;
const ENFORCE_DOMAIN: u8 = 12;

/// A malformed private producer record.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum DecodeError {
    /// The sample does not have the producer's exact fixed size.
    #[non_exhaustive]
    Length {
        /// The producer's fixed record size.
        expected: usize,
        /// The supplied sample size.
        actual: usize,
    },
    /// A known boolean field is neither zero nor one.
    #[non_exhaustive]
    Boolean {
        /// The semantic field name.
        field: &'static str,
        /// The invalid field value.
        value: u8,
    },
    /// Captured bytes violate their origin's semantic domain.
    #[non_exhaustive]
    CapturedBytes {
        /// The semantic field name.
        field: &'static str,
        /// The origin-specific validation failure.
        source: CapturedBytesError,
    },
    /// An abstract UNIX socket name length exceeds its wire capacity.
    #[non_exhaustive]
    AbstractUnixSocketNameLength {
        /// The invalid length.
        value: u32,
        /// The inclusive maximum valid length.
        maximum: usize,
    },
    /// A Landlock ID field is below the kernel-assigned range, including zero.
    #[non_exhaustive]
    Id {
        /// The semantic field name.
        field: &'static str,
        /// The invalid field value.
        value: u64,
    },
    /// A mandatory process or thread ID field is zero.
    #[non_exhaustive]
    TaskId {
        /// The semantic field name.
        field: &'static str,
    },
    /// The private producer record has an unrecognized event kind.
    #[non_exhaustive]
    EventKind {
        /// The unrecognized numeric kind.
        value: u8,
    },
    /// A fixed field could not be read from an otherwise sized record.
    #[non_exhaustive]
    Field {
        /// The semantic field name.
        field: &'static str,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(
                    formatter,
                    "invalid event record length {actual}, expected {expected}"
                )
            }
            Self::Boolean { field, value } => {
                write!(formatter, "invalid boolean {field}: {value}")
            }
            Self::CapturedBytes { field, source } => {
                write!(formatter, "invalid captured bytes for {field}: {source}")
            }
            Self::AbstractUnixSocketNameLength { value, maximum } => write!(
                formatter,
                "invalid abstract UNIX socket name length {value}, maximum is {maximum}"
            ),
            Self::Id { field, value } => write!(formatter, "invalid Landlock ID {field}: {value}"),
            Self::TaskId { field } => write!(formatter, "invalid task ID {field}: 0"),
            Self::EventKind { value } => write!(formatter, "unrecognized event kind {value}"),
            Self::Field { field } => write!(formatter, "invalid field {field}"),
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CapturedBytes { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn slice_at<'a>(
    data: &'a [u8],
    offset: usize,
    size: usize,
    field: &'static str,
) -> Result<&'a [u8], DecodeError> {
    let end = offset
        .checked_add(size)
        .ok_or(DecodeError::Field { field })?;
    data.get(offset..end).ok_or(DecodeError::Field { field })
}

fn bytes<const N: usize>(
    data: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; N], DecodeError> {
    slice_at(data, offset, N, field)?
        .try_into()
        .map_err(|_| DecodeError::Field { field })
}

fn u32_at(data: &[u8], offset: usize, field: &'static str) -> Result<u32, DecodeError> {
    Ok(u32::from_ne_bytes(bytes(data, offset, field)?))
}

fn u64_at(data: &[u8], offset: usize, field: &'static str) -> Result<u64, DecodeError> {
    Ok(u64::from_ne_bytes(bytes(data, offset, field)?))
}

fn captured_c_string<K: CapturedBytesOrigin>(
    value: &[u8],
    bytes_omitted: bool,
    field: &'static str,
) -> Result<CapturedBytes<K>, DecodeError> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    let value = value.get(..end).ok_or(DecodeError::Field { field })?;
    CapturedBytes::new(value.to_vec(), bytes_omitted)
        .map_err(|source| DecodeError::CapturedBytes { field, source })
}

fn captured_at<K: CapturedBytesOrigin>(
    data: &[u8],
    offset: usize,
    size: usize,
    omitted_offset: usize,
    field: &'static str,
    omitted_field: &'static str,
) -> Result<CapturedBytes<K>, DecodeError> {
    let value = slice_at(data, offset, size, field)?;
    let bytes_omitted = boolean_at(data, omitted_offset, omitted_field)?;
    captured_c_string(value, bytes_omitted, field)
}

fn abstract_unix_socket_name_at(
    data: &[u8],
    length_offset: usize,
    name_offset: usize,
) -> Result<CapturedAbstractUnixSocketName, DecodeError> {
    const FIELD: &str = "abstract_unix_socket_name";

    let length = u32_at(data, length_offset, "abstract_unix_socket_name_length")?;
    if length > ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN as u32 {
        return Err(DecodeError::AbstractUnixSocketNameLength {
            value: length,
            maximum: ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN,
        });
    }
    let length = length as usize;
    let value = slice_at(data, name_offset, length, FIELD)?;
    CapturedAbstractUnixSocketName::new(value.to_vec(), false).map_err(|source| {
        DecodeError::CapturedBytes {
            field: FIELD,
            source,
        }
    })
}

fn command_at(
    data: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<CapturedCommand, DecodeError> {
    let value = slice_at(data, offset, COMM_SIZE, field)?;
    // Kernel command sources are NUL-terminated TASK_COMM_LEN arrays, so the
    // complete command always fits in the fixed field.
    captured_c_string(value, false, field)
}

fn boolean_at(data: &[u8], offset: usize, field: &'static str) -> Result<bool, DecodeError> {
    let value = *data.get(offset).ok_or(DecodeError::Field { field })?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::Boolean { field, value }),
    }
}

fn id<K: LandlockIdKind>(value: u64, field: &'static str) -> Result<LandlockId<K>, DecodeError> {
    LandlockId::new(value).map_err(|_| DecodeError::Id { field, value })
}

fn process_id(value: u32, field: &'static str) -> Result<ProcessId, DecodeError> {
    ProcessId::new(value).map_err(|_| DecodeError::TaskId { field })
}

fn thread_id(value: u32, field: &'static str) -> Result<ThreadId, DecodeError> {
    ThreadId::new(value).map_err(|_| DecodeError::TaskId { field })
}

fn optional_process_id(value: u32) -> Option<ProcessId> {
    ProcessId::new(value).ok()
}

fn parent(value: u64, field: &'static str) -> Result<Option<DomainId>, DecodeError> {
    if value == 0 {
        Ok(None)
    } else {
        id(value, field).map(Some)
    }
}

fn domain_membership(value: u64, field: &'static str) -> Result<DomainMembership, DecodeError> {
    if value == 0 {
        Ok(DomainMembership::Unsandboxed)
    } else {
        id(value, field).map(DomainMembership::Sandboxed)
    }
}

fn denial_context(data: &[u8]) -> Result<DenialContext, DecodeError> {
    Ok(DenialContext::builder()
        .hierarchy(
            HierarchySnapshot::builder()
                .domain_id(id(u64_at(data, UNION_OFFSET, "domain_id")?, "domain_id")?)
                .parent_id(parent(u64_at(data, 24, "parent_id")?, "parent_id")?)
                .creator_tgid(process_id(
                    u32_at(data, 32, "creator_tgid")?,
                    "creator_tgid",
                )?)
                .creator_comm(command_at(data, 36, "creator_comm")?)
                .build(),
        )
        .cumulative_denial_count(u64_at(data, 56, "cumulative_denial_count")?)
        .same_exec(boolean_at(data, 72, "same_exec")?)
        .logged(boolean_at(data, 73, "logged")?)
        .build())
}

/// Decodes one complete private producer record into a semantic event.
pub(crate) fn decode(data: &[u8]) -> Result<Event, DecodeError> {
    if data.len() != RECORD_SIZE {
        return Err(DecodeError::Length {
            expected: RECORD_SIZE,
            actual: data.len(),
        });
    }

    let event_type = *data.get(TYPE_OFFSET).ok_or(DecodeError::Field {
        field: "event_type",
    })?;
    let timestamp = KernelTimestamp::from_nanoseconds(u64_at(data, TIMESTAMP_OFFSET, "timestamp")?);

    let event = match event_type {
        CREATE_RULESET => Event::CreateRuleset(
            CreateRulesetEvent::builder()
                .timestamp(timestamp)
                .ruleset_id(id(u64_at(data, 16, "ruleset_id")?, "ruleset_id")?)
                .ruleset_version(u64_at(data, 24, "ruleset_version")?)
                .handled_fs(FilesystemAccess::from_bits(u64_at(data, 32, "handled_fs")?))
                .handled_net(NetworkAccess::from_bits(u64_at(data, 40, "handled_net")?))
                .scoped(ScopeAccess::from_bits(u64_at(data, 48, "scoped")?))
                .build(),
        ),
        ADD_RULE_PATH_BENEATH => Event::AddRulePathBeneath(
            AddRulePathBeneathEvent::builder()
                .timestamp(timestamp)
                .ruleset_id(id(u64_at(data, 16, "ruleset_id")?, "ruleset_id")?)
                .ruleset_version(u64_at(data, 24, "ruleset_version")?)
                .access_rights(FilesystemAccess::from_bits(u64_at(
                    data,
                    32,
                    "access_rights",
                )?))
                .device(u32_at(data, 40, "device")?)
                .inode(u64_at(data, 48, "inode")?)
                .pathname(captured_at(
                    data,
                    56,
                    PATH_SIZE,
                    44,
                    "pathname",
                    "pathname_bytes_omitted",
                )?)
                .build(),
        ),
        ADD_RULE_NET_PORT => Event::AddRuleNetPort(
            AddRuleNetPortEvent::builder()
                .timestamp(timestamp)
                .ruleset_id(id(u64_at(data, 16, "ruleset_id")?, "ruleset_id")?)
                .ruleset_version(u64_at(data, 24, "ruleset_version")?)
                .access_rights(NetworkAccess::from_bits(u64_at(data, 32, "access_rights")?))
                .port(u64_at(data, 40, "port")?)
                .build(),
        ),
        CREATE_DOMAIN => Event::CreateDomain(
            CreateDomainEvent::builder()
                .timestamp(timestamp)
                .ruleset_id(id(u64_at(data, 16, "ruleset_id")?, "ruleset_id")?)
                .ruleset_version(u64_at(data, 24, "ruleset_version")?)
                .domain_id(id(u64_at(data, 32, "domain_id")?, "domain_id")?)
                .parent_id(parent(u64_at(data, 40, "parent_id")?, "parent_id")?)
                .creator_tgid(process_id(
                    u32_at(data, 48, "creator_tgid")?,
                    "creator_tgid",
                )?)
                .creator_comm(command_at(data, 52, "creator_comm")?)
                .build(),
        ),
        DENY_ACCESS_FS => Event::DenyAccessFs(
            DenyAccessFsEvent::builder()
                .timestamp(timestamp)
                .context(denial_context(data)?)
                .blockers_type(BlockerType::from_raw(u32_at(data, 52, "blockers_type")?))
                .blockers_access(FilesystemAccess::from_bits(u64_at(
                    data,
                    64,
                    "blockers_access",
                )?))
                .device(u32_at(data, 80, "device")?)
                .inode(u64_at(data, 88, "inode")?)
                .pathname(captured_at(
                    data,
                    96,
                    PATH_SIZE,
                    84,
                    "pathname",
                    "pathname_bytes_omitted",
                )?)
                .build(),
        ),
        DENY_ACCESS_NET => Event::DenyAccessNet(
            DenyAccessNetEvent::builder()
                .timestamp(timestamp)
                .context(denial_context(data)?)
                .blockers_type(BlockerType::from_raw(u32_at(data, 52, "blockers_type")?))
                .blockers_access(NetworkAccess::from_bits(u64_at(
                    data,
                    64,
                    "blockers_access",
                )?))
                .source_port(u64_at(data, 80, "source_port")?)
                .destination_port(u64_at(data, 88, "destination_port")?)
                .build(),
        ),
        DENY_PTRACE => Event::DenyPtrace(
            DenyPtraceEvent::builder()
                .timestamp(timestamp)
                .context(denial_context(data)?)
                .tracee_domain(domain_membership(
                    u64_at(data, 80, "tracee_domain")?,
                    "tracee_domain",
                )?)
                .tracee_pid(process_id(u32_at(data, 88, "tracee_pid")?, "tracee_pid")?)
                .tracee_comm(command_at(data, 92, "tracee_comm")?)
                .build(),
        ),
        DENY_SCOPE_SIGNAL => Event::DenyScopeSignal(
            DenyScopeSignalEvent::builder()
                .timestamp(timestamp)
                .context(denial_context(data)?)
                .target_domain(domain_membership(
                    u64_at(data, 80, "target_domain")?,
                    "target_domain",
                )?)
                .target_pid(process_id(u32_at(data, 88, "target_pid")?, "target_pid")?)
                .target_comm(command_at(data, 92, "target_comm")?)
                .build(),
        ),
        DENY_SCOPE_ABSTRACT_UNIX_SOCKET => Event::DenyScopeAbstractUnixSocket(
            DenyScopeAbstractUnixSocketEvent::builder()
                .timestamp(timestamp)
                .context(denial_context(data)?)
                .peer_domain(domain_membership(
                    u64_at(data, 80, "peer_domain")?,
                    "peer_domain",
                )?)
                .peer_pid(optional_process_id(u32_at(data, 88, "peer_pid")?))
                .abstract_name(abstract_unix_socket_name_at(data, 92, 96)?)
                .build(),
        ),
        FREE_DOMAIN => Event::FreeDomain(
            FreeDomainEvent::builder()
                .timestamp(timestamp)
                .domain_id(id(u64_at(data, 16, "domain_id")?, "domain_id")?)
                .denial_count(u64_at(data, 24, "denial_count")?)
                .build(),
        ),
        FREE_RULESET => Event::FreeRuleset(
            FreeRulesetEvent::builder()
                .timestamp(timestamp)
                .ruleset_id(id(u64_at(data, 16, "ruleset_id")?, "ruleset_id")?)
                .ruleset_version(u64_at(data, 24, "ruleset_version")?)
                .build(),
        ),
        ENFORCE_DOMAIN => Event::EnforceDomain(
            EnforceDomainEvent::builder()
                .timestamp(timestamp)
                .domain_id(id(u64_at(data, 16, "domain_id")?, "domain_id")?)
                .enforcing_tid(thread_id(
                    u32_at(data, 24, "enforcing_tid")?,
                    "enforcing_tid",
                )?)
                .complete(boolean_at(data, 28, "complete")?)
                .process_wide(boolean_at(data, 29, "process_wide")?)
                .no_new_privs(boolean_at(data, 30, "no_new_privs")?)
                .build(),
        ),
        _ => return Err(DecodeError::EventKind { value: event_type }),
    };
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CapturedCommand, Denial, Observation, RulesetId};

    #[cfg(target_endian = "little")]
    const FIXTURES: [&[u8; RECORD_SIZE]; 12] = [
        include_bytes!("../tests/fixtures/wire/01-ruleset-create-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/02-fs-rule-add-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/03-network-rule-add-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/04-domain-create-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/05-fs-denial-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/06-network-denial-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/07-ptrace-denial-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/08-signal-denial-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/09-abstract-unix-denial-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/10-domain-free-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-little-endian.bin"),
        include_bytes!("../tests/fixtures/wire/12-domain-enforce-little-endian.bin"),
    ];

    #[cfg(target_endian = "big")]
    const FIXTURES: [&[u8; RECORD_SIZE]; 12] = [
        include_bytes!("../tests/fixtures/wire/01-ruleset-create-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/02-fs-rule-add-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/03-network-rule-add-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/04-domain-create-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/05-fs-denial-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/06-network-denial-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/07-ptrace-denial-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/08-signal-denial-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/09-abstract-unix-denial-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/10-domain-free-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-big-endian.bin"),
        include_bytes!("../tests/fixtures/wire/12-domain-enforce-big-endian.bin"),
    ];

    fn captured<K: CapturedBytesOrigin>(
        bytes: impl AsRef<[u8]>,
        bytes_omitted: bool,
    ) -> CapturedBytes<K> {
        CapturedBytes::new(bytes.as_ref().to_vec(), bytes_omitted).unwrap()
    }

    fn pid(value: u32) -> ProcessId {
        ProcessId::new(value).unwrap()
    }

    fn tid(value: u32) -> ThreadId {
        ThreadId::new(value).unwrap()
    }

    fn context(
        domain_id: u64,
        parent_id: Option<u64>,
        creator_tgid: u32,
        creator_comm: CapturedCommand,
        cumulative_denial_count: u64,
        same_exec: bool,
        logged: bool,
    ) -> DenialContext {
        DenialContext::builder()
            .hierarchy(
                HierarchySnapshot::builder()
                    .domain_id(DomainId::new(domain_id).unwrap())
                    .parent_id(parent_id.map(|parent_id| DomainId::new(parent_id).unwrap()))
                    .creator_tgid(pid(creator_tgid))
                    .creator_comm(creator_comm)
                    .build(),
            )
            .cumulative_denial_count(cumulative_denial_count)
            .same_exec(same_exec)
            .logged(logged)
            .build()
    }

    fn generic_timestamp<T: Observation>(observation: &T) -> KernelTimestamp {
        observation.timestamp()
    }

    fn generic_context<T: Denial>(denial: &T) -> &DenialContext {
        denial.context()
    }

    fn assert_concrete_trait_dispatch(event: &Event) {
        let timestamp = match event {
            Event::CreateRuleset(value) => generic_timestamp(value),
            Event::AddRulePathBeneath(value) => generic_timestamp(value),
            Event::AddRuleNetPort(value) => generic_timestamp(value),
            Event::CreateDomain(value) => generic_timestamp(value),
            Event::DenyAccessFs(value) => {
                let _ = generic_context(value);
                generic_timestamp(value)
            }
            Event::DenyAccessNet(value) => {
                let _ = generic_context(value);
                generic_timestamp(value)
            }
            Event::DenyPtrace(value) => {
                let _ = generic_context(value);
                generic_timestamp(value)
            }
            Event::DenyScopeSignal(value) => {
                let _ = generic_context(value);
                generic_timestamp(value)
            }
            Event::DenyScopeAbstractUnixSocket(value) => {
                let _ = generic_context(value);
                generic_timestamp(value)
            }
            Event::FreeDomain(value) => generic_timestamp(value),
            Event::FreeRuleset(value) => generic_timestamp(value),
            Event::EnforceDomain(value) => generic_timestamp(value),
        };
        assert_eq!(generic_timestamp(event), timestamp);
    }

    #[test]
    fn traits_dispatch_every_event_family() {
        for fixture in FIXTURES {
            assert_concrete_trait_dispatch(&decode(fixture).unwrap());
        }
    }

    #[test]
    fn decodes_all_fixture_fields() {
        let expected = [
            Event::CreateRuleset(
                CreateRulesetEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x1100000000000001))
                    .ruleset_id(RulesetId::new(0xA100000000000001).unwrap())
                    .ruleset_version(0x1200000112000001)
                    .handled_fs(FilesystemAccess::from_bits(0x8000000080010005))
                    .handled_net(NetworkAccess::from_bits(0x800000008000000A))
                    .scoped(ScopeAccess::from_bits(0x8000000080000003))
                    .build(),
            ),
            Event::AddRulePathBeneath(
                AddRulePathBeneathEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x2200000000000002))
                    .ruleset_id(RulesetId::new(0xA200000000000002).unwrap())
                    .ruleset_version(0x2300000223000002)
                    .access_rights(FilesystemAccess::from_bits(0x8000000080004006))
                    .device(0x34000002)
                    .inode(0x4500000000000002)
                    .pathname(captured(b"/fixture/\xff\x1b", false))
                    .build(),
            ),
            Event::AddRuleNetPort(
                AddRuleNetPortEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x3300000000000003))
                    .ruleset_id(RulesetId::new(0xA300000000000003).unwrap())
                    .ruleset_version(0x3400000334000003)
                    .access_rights(NetworkAccess::from_bits(0x8000000080000009))
                    .port(0x5600000000000003)
                    .build(),
            ),
            Event::CreateDomain(
                CreateDomainEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x4400000000000004))
                    .ruleset_id(RulesetId::new(0xA400000000000004).unwrap())
                    .ruleset_version(0x4500000445000004)
                    .domain_id(DomainId::new(0xD400000000000004).unwrap())
                    .parent_id(None)
                    .creator_tgid(pid(0x56000004))
                    .creator_comm(captured(b"15-byte-command", false))
                    .build(),
            ),
            Event::DenyAccessFs(
                DenyAccessFsEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x5500000000000005))
                    .context(context(
                        0xD000000000000005,
                        None,
                        0x51000005,
                        captured(b"creator-5", false),
                        0xC100000000000005,
                        true,
                        false,
                    ))
                    .blockers_type(BlockerType::FS_ACCESS)
                    .blockers_access(FilesystemAccess::from_bits(0x8000000080010005))
                    .device(0x72000005)
                    .inode(0x8300000000000005)
                    .pathname(captured(vec![b'P'; 256], true))
                    .build(),
            ),
            Event::DenyAccessNet(
                DenyAccessNetEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x6600000000000006))
                    .context(context(
                        0xD000000000000006,
                        Some(0xA000000000000006),
                        0x51000006,
                        captured(b"creator-6", false),
                        0xC100000000000006,
                        false,
                        true,
                    ))
                    .blockers_type(BlockerType::NET_ACCESS)
                    .blockers_access(NetworkAccess::from_bits(0x8000000080010006))
                    .source_port(0x7400000000000006)
                    .destination_port(0x8500000000000006)
                    .build(),
            ),
            Event::DenyPtrace(
                DenyPtraceEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x7700000000000007))
                    .context(context(
                        0xD000000000000007,
                        Some(0xA000000000000007),
                        0x51000007,
                        captured(b"creator-7", false),
                        0xC100000000000007,
                        true,
                        true,
                    ))
                    .tracee_domain(DomainMembership::Unsandboxed)
                    .tracee_pid(pid(0x86000007))
                    .tracee_comm(captured(b"ptrace-target", false))
                    .build(),
            ),
            Event::DenyScopeSignal(
                DenyScopeSignalEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x8800000000000008))
                    .context(context(
                        0xD000000000000008,
                        Some(0xA000000000000008),
                        0x51000008,
                        captured(b"creator-8", false),
                        0xC100000000000008,
                        false,
                        false,
                    ))
                    .target_domain(DomainMembership::Sandboxed(
                        DomainId::new(0xE800000000000008).unwrap(),
                    ))
                    .target_pid(pid(0x97000008))
                    .target_comm(captured(b"signal-target", false))
                    .build(),
            ),
            Event::DenyScopeAbstractUnixSocket(
                DenyScopeAbstractUnixSocketEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0x9900000000000009))
                    .context(context(
                        0xD000000000000009,
                        Some(0xA000000000000009),
                        0x51000009,
                        captured(b"15-byte-command", false),
                        0xC100000000000009,
                        true,
                        false,
                    ))
                    .peer_domain(DomainMembership::Sandboxed(
                        DomainId::new(0xE900000000000009).unwrap(),
                    ))
                    .peer_pid(Some(pid(0xA8000009)))
                    .abstract_name(captured(b"service\0\xff\0", false))
                    .build(),
            ),
            Event::FreeDomain(
                FreeDomainEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0xAA0000000000000A))
                    .domain_id(DomainId::new(0xDA0000000000000A).unwrap())
                    .denial_count(0xAB0000000000000A)
                    .build(),
            ),
            Event::FreeRuleset(
                FreeRulesetEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0xBB0000000000000B))
                    .ruleset_id(RulesetId::new(0xAB0000000000000B).unwrap())
                    .ruleset_version(0xBC00000BBC00000B)
                    .build(),
            ),
            Event::EnforceDomain(
                EnforceDomainEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(0xCC0000000000000C))
                    .domain_id(DomainId::new(0xDC0000000000000C).unwrap())
                    .enforcing_tid(tid(0xCD00000C))
                    .complete(true)
                    .process_wide(false)
                    .no_new_privs(true)
                    .build(),
            ),
        ];

        for (fixture, expected) in FIXTURES.iter().zip(expected) {
            let decoded = decode(fixture.as_slice()).unwrap();
            assert_eq!(decoded.timestamp(), expected.timestamp());
            assert_eq!(decoded, expected);
        }
    }

    fn assert_context(
        value: &DenialContext,
        domain_id: u64,
        parent_id: Option<u64>,
        creator_tgid: u32,
        creator_comm: (&[u8], bool),
        count: u64,
        flags: (bool, bool),
    ) {
        assert_eq!(
            value.hierarchy().domain_id(),
            DomainId::new(domain_id).unwrap()
        );
        assert_eq!(
            value.hierarchy().parent_id(),
            parent_id.map(|parent_id| DomainId::new(parent_id).unwrap())
        );
        assert_eq!(value.hierarchy().creator_tgid().get(), creator_tgid);
        assert_eq!(value.hierarchy().creator_comm().as_bytes(), creator_comm.0);
        assert_eq!(
            value.hierarchy().creator_comm().bytes_omitted(),
            creator_comm.1
        );
        assert_eq!(value.cumulative_denial_count(), count);
        assert_eq!(value.same_exec(), flags.0);
        assert_eq!(value.logged(), flags.1);
    }

    #[test]
    fn decoded_public_accessors() {
        let Event::CreateRuleset(value) = decode(FIXTURES[0]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x1100000000000001);
        assert_eq!(
            value.ruleset_id(),
            RulesetId::new(0xA100000000000001).unwrap()
        );
        assert_eq!(value.ruleset_version(), 0x1200000112000001);
        assert_eq!(value.handled_fs().bits(), 0x8000000080010005);
        assert_eq!(value.handled_net().bits(), 0x800000008000000A);
        assert_eq!(value.scoped().bits(), 0x8000000080000003);

        let Event::AddRulePathBeneath(value) = decode(FIXTURES[1]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x2200000000000002);
        assert_eq!(
            value.ruleset_id(),
            RulesetId::new(0xA200000000000002).unwrap()
        );
        assert_eq!(value.ruleset_version(), 0x2300000223000002);
        assert_eq!(value.access_rights().bits(), 0x8000000080004006);
        assert_eq!(value.device(), 0x34000002);
        assert_eq!(value.inode(), 0x4500000000000002);
        assert_eq!(value.pathname().as_bytes(), b"/fixture/\xff\x1b");

        let Event::AddRuleNetPort(value) = decode(FIXTURES[2]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x3300000000000003);
        assert_eq!(
            value.ruleset_id(),
            RulesetId::new(0xA300000000000003).unwrap()
        );
        assert_eq!(value.ruleset_version(), 0x3400000334000003);
        assert_eq!(value.access_rights().bits(), 0x8000000080000009);
        assert_eq!(value.port(), 0x5600000000000003);

        let Event::CreateDomain(value) = decode(FIXTURES[3]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x4400000000000004);
        assert_eq!(
            value.ruleset_id(),
            RulesetId::new(0xA400000000000004).unwrap()
        );
        assert_eq!(value.ruleset_version(), 0x4500000445000004);
        assert_eq!(
            value.domain_id(),
            DomainId::new(0xD400000000000004).unwrap()
        );
        assert_eq!(value.parent_id(), None);
        assert_eq!(value.creator_tgid().get(), 0x56000004);
        assert_eq!(value.creator_comm().as_bytes(), b"15-byte-command");

        let Event::DenyAccessFs(value) = decode(FIXTURES[4]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x5500000000000005);
        assert_context(
            value.context(),
            0xD000000000000005,
            None,
            0x51000005,
            (b"creator-5", false),
            0xC100000000000005,
            (true, false),
        );
        assert_eq!(value.blockers_type(), BlockerType::FS_ACCESS);
        assert_eq!(value.blockers_access().bits(), 0x8000000080010005);
        assert_eq!(value.device(), 0x72000005);
        assert_eq!(value.inode(), 0x8300000000000005);
        assert_eq!(value.pathname().as_bytes(), vec![b'P'; 256]);

        let Event::DenyAccessNet(value) = decode(FIXTURES[5]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x6600000000000006);
        assert_context(
            value.context(),
            0xD000000000000006,
            Some(0xA000000000000006),
            0x51000006,
            (b"creator-6", false),
            0xC100000000000006,
            (false, true),
        );
        assert_eq!(value.blockers_type(), BlockerType::NET_ACCESS);
        assert_eq!(value.blockers_access().bits(), 0x8000000080010006);
        assert_eq!(value.source_port(), 0x7400000000000006);
        assert_eq!(value.destination_port(), 0x8500000000000006);

        let Event::DenyPtrace(value) = decode(FIXTURES[6]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x7700000000000007);
        assert_context(
            value.context(),
            0xD000000000000007,
            Some(0xA000000000000007),
            0x51000007,
            (b"creator-7", false),
            0xC100000000000007,
            (true, true),
        );
        assert_eq!(value.tracee_domain(), DomainMembership::Unsandboxed);
        assert_eq!(value.tracee_pid().get(), 0x86000007);
        assert_eq!(value.tracee_comm().as_bytes(), b"ptrace-target");

        let Event::DenyScopeSignal(value) = decode(FIXTURES[7]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x8800000000000008);
        assert_context(
            value.context(),
            0xD000000000000008,
            Some(0xA000000000000008),
            0x51000008,
            (b"creator-8", false),
            0xC100000000000008,
            (false, false),
        );
        assert_eq!(
            value.target_domain(),
            DomainMembership::Sandboxed(DomainId::new(0xE800000000000008).unwrap())
        );
        assert_eq!(value.target_pid().get(), 0x97000008);
        assert_eq!(value.target_comm().as_bytes(), b"signal-target");

        let Event::DenyScopeAbstractUnixSocket(value) = decode(FIXTURES[8]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x9900000000000009);
        assert_context(
            value.context(),
            0xD000000000000009,
            Some(0xA000000000000009),
            0x51000009,
            (b"15-byte-command", false),
            0xC100000000000009,
            (true, false),
        );
        assert_eq!(
            value.peer_domain(),
            DomainMembership::Sandboxed(DomainId::new(0xE900000000000009).unwrap())
        );
        assert_eq!(value.peer_pid().map(ProcessId::get), Some(0xA8000009));
        assert_eq!(value.abstract_name().as_bytes(), b"service\0\xff\0");

        let Event::FreeDomain(value) = decode(FIXTURES[9]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xAA0000000000000A);
        assert_eq!(
            value.domain_id(),
            DomainId::new(0xDA0000000000000A).unwrap()
        );
        assert_eq!(value.denial_count(), 0xAB0000000000000A);

        let Event::FreeRuleset(value) = decode(FIXTURES[10]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xBB0000000000000B);
        assert_eq!(
            value.ruleset_id(),
            RulesetId::new(0xAB0000000000000B).unwrap()
        );
        assert_eq!(value.ruleset_version(), 0xBC00000BBC00000B);

        let Event::EnforceDomain(value) = decode(FIXTURES[11]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xCC0000000000000C);
        assert_eq!(
            value.domain_id(),
            DomainId::new(0xDC0000000000000C).unwrap()
        );
        assert_eq!(value.enforcing_tid().get(), 0xCD00000C);
        assert!(value.complete());
        assert!(!value.process_wide());
        assert!(value.no_new_privs());
    }

    #[test]
    fn preserves_unknown_blocker_types() {
        let mut data = FIXTURES[4].to_vec();
        data[52..56].copy_from_slice(&u32::MAX.to_ne_bytes());
        let Event::DenyAccessFs(value) = decode(&data).unwrap() else {
            panic!()
        };
        assert_eq!(value.blockers_type().raw(), u32::MAX);
        assert_eq!(value.blockers_access().bits(), 0x8000000080010005);
    }

    #[test]
    fn decodes_both_no_new_privs_values() {
        let mut data = *FIXTURES[11];
        let Event::EnforceDomain(one) = decode(&data).unwrap() else {
            panic!()
        };
        assert!(one.no_new_privs());
        data[30] = 0;
        let Event::EnforceDomain(zero) = decode(&data).unwrap() else {
            panic!()
        };
        assert!(!zero.no_new_privs());
    }

    #[test]
    fn requires_exact_record_length_before_kind() {
        assert_eq!(
            decode(&FIXTURES[0][..RECORD_SIZE - 1]),
            Err(DecodeError::Length {
                expected: RECORD_SIZE,
                actual: RECORD_SIZE - 1
            })
        );
        let mut longer = FIXTURES[0].to_vec();
        longer.push(0);
        assert_eq!(
            decode(&longer),
            Err(DecodeError::Length {
                expected: RECORD_SIZE,
                actual: RECORD_SIZE + 1
            })
        );
    }

    #[test]
    fn rejects_unknown_private_event_kind() {
        let mut data = *FIXTURES[0];
        data[TYPE_OFFSET] = 0xF3;
        let error = DecodeError::EventKind { value: 0xF3 };
        assert_eq!(decode(&data), Err(error.clone()));
        assert_eq!(error.to_string(), "unrecognized event kind 243");
    }

    #[test]
    fn checked_field_errors_expose_only_semantic_context() {
        assert_eq!(
            bytes::<8>(&[0; 7], 0, "semantic_field"),
            Err(DecodeError::Field {
                field: "semantic_field"
            })
        );
        assert_eq!(
            bytes::<1>(&[0], usize::MAX, "semantic_field"),
            Err(DecodeError::Field {
                field: "semantic_field"
            })
        );
        assert_eq!(
            DecodeError::Field {
                field: "semantic_field"
            }
            .to_string(),
            "invalid field semantic_field"
        );
    }

    #[test]
    fn validates_id_boundaries_and_zero_sentinels() {
        let mut ruleset = *FIXTURES[0];
        ruleset[16..24].copy_from_slice(&0xffff_ffff_u64.to_ne_bytes());
        let error = DecodeError::Id {
            field: "ruleset_id",
            value: 0xffff_ffff,
        };
        assert_eq!(decode(&ruleset), Err(error.clone()));
        assert_eq!(
            error.to_string(),
            "invalid Landlock ID ruleset_id: 4294967295"
        );

        ruleset[16..24].copy_from_slice(&0x1_0000_0000_u64.to_ne_bytes());
        let Event::CreateRuleset(event) = decode(&ruleset).unwrap() else {
            panic!()
        };
        assert_eq!(event.ruleset_id().get(), 0x1_0000_0000);

        for (fixture, offset, field) in [
            (3, 32, "domain_id"),
            (5, 24, "parent_id"),
            (7, 80, "target_domain"),
        ] {
            let mut data = *FIXTURES[fixture];
            data[offset..offset + 8].copy_from_slice(&1_u64.to_ne_bytes());
            assert_eq!(decode(&data), Err(DecodeError::Id { field, value: 1 }));
        }

        let mut root = *FIXTURES[3];
        root[40..48].copy_from_slice(&0_u64.to_ne_bytes());
        let Event::CreateDomain(root) = decode(&root).unwrap() else {
            panic!()
        };
        assert_eq!(root.parent_id(), None);

        let mut unsandboxed = *FIXTURES[7];
        unsandboxed[80..88].copy_from_slice(&0_u64.to_ne_bytes());
        let Event::DenyScopeSignal(unsandboxed) = decode(&unsandboxed).unwrap() else {
            panic!()
        };
        assert_eq!(unsandboxed.target_domain(), DomainMembership::Unsandboxed);
    }

    #[test]
    fn validates_mandatory_task_ids_and_optional_peer_pid() {
        for (fixture, offset, field) in [
            (3, 48, "creator_tgid"),
            (4, 32, "creator_tgid"),
            (5, 32, "creator_tgid"),
            (6, 32, "creator_tgid"),
            (7, 32, "creator_tgid"),
            (8, 32, "creator_tgid"),
            (6, 88, "tracee_pid"),
            (7, 88, "target_pid"),
            (11, 24, "enforcing_tid"),
        ] {
            let mut data = *FIXTURES[fixture];
            data[offset..offset + size_of::<u32>()].copy_from_slice(&0_u32.to_ne_bytes());
            assert_eq!(decode(&data), Err(DecodeError::TaskId { field }));
        }
        assert_eq!(
            DecodeError::TaskId {
                field: "tracee_pid"
            }
            .to_string(),
            "invalid task ID tracee_pid: 0"
        );

        let mut data = *FIXTURES[8];
        data[88..92].copy_from_slice(&0_u32.to_ne_bytes());
        let Event::DenyScopeAbstractUnixSocket(event) = decode(&data).unwrap() else {
            panic!()
        };
        assert_eq!(event.peer_pid(), None);
    }

    #[test]
    fn abstract_unix_socket_name_length_is_exact_and_bounded() {
        let mut empty = *FIXTURES[8];
        empty[92..96].copy_from_slice(&0_u32.to_ne_bytes());
        let Event::DenyScopeAbstractUnixSocket(empty) = decode(&empty).unwrap() else {
            panic!()
        };
        assert!(empty.abstract_name().as_bytes().is_empty());

        let mut maximum = *FIXTURES[8];
        maximum[92..96].copy_from_slice(&107_u32.to_ne_bytes());
        maximum[96..203].copy_from_slice(&[0xa5; 107]);
        let Event::DenyScopeAbstractUnixSocket(maximum) = decode(&maximum).unwrap() else {
            panic!()
        };
        assert_eq!(maximum.abstract_name().as_bytes(), &[0xa5; 107]);

        for invalid in [108, u32::MAX] {
            let mut malformed = *FIXTURES[8];
            malformed[92..96].copy_from_slice(&invalid.to_ne_bytes());
            assert_eq!(
                decode(&malformed),
                Err(DecodeError::AbstractUnixSocketNameLength {
                    value: invalid,
                    maximum: 107,
                })
            );
        }
    }

    #[test]
    fn rejects_every_invalid_boolean_value() {
        for (fixture, offset, field) in [
            (4, 72, "same_exec"),
            (4, 73, "logged"),
            (1, 44, "pathname_bytes_omitted"),
            (4, 84, "pathname_bytes_omitted"),
            (11, 28, "complete"),
            (11, 29, "process_wide"),
            (11, 30, "no_new_privs"),
        ] {
            for value in [2, 255] {
                let mut data = *FIXTURES[fixture];
                data[offset] = value;
                let error = DecodeError::Boolean { field, value };
                assert_eq!(decode(&data), Err(error.clone()));
                assert_eq!(
                    error.to_string(),
                    format!("invalid boolean {field}: {value}")
                );
            }
        }
    }

    #[test]
    fn strings_preserve_bytes_and_bounds() {
        let Event::AddRulePathBeneath(event) = decode(FIXTURES[1]).unwrap() else {
            panic!()
        };
        assert_eq!(event.pathname().as_bytes(), b"/fixture/\xff\x1b");
        assert!(!event.pathname().bytes_omitted());
        assert_eq!(event.pathname().to_string_lossy(), "/fixture/�\u{1b}");

        let Event::DenyAccessFs(omitted) = decode(FIXTURES[4]).unwrap() else {
            panic!()
        };
        assert_eq!(omitted.pathname().as_bytes(), &[b'P'; PATH_SIZE]);
        assert!(omitted.pathname().bytes_omitted());

        let mut exact_fit = *FIXTURES[1];
        exact_fit[56..56 + PATH_SIZE].fill(b'E');
        exact_fit[44] = 0;
        let Event::AddRulePathBeneath(exact_fit) = decode(&exact_fit).unwrap() else {
            panic!()
        };
        assert_eq!(exact_fit.pathname().as_bytes(), &[b'E'; PATH_SIZE]);
        assert!(!exact_fit.pathname().bytes_omitted());

        let Event::CreateDomain(event) = decode(FIXTURES[3]).unwrap() else {
            panic!()
        };
        assert_eq!(event.creator_comm().as_bytes(), b"15-byte-command");
        assert!(!event.creator_comm().bytes_omitted());
    }

    #[test]
    fn rejects_producer_impossible_fixed_captures() {
        let mut command = *FIXTURES[3];
        command[52..52 + COMM_SIZE].fill(b'C');
        let command_error = DecodeError::CapturedBytes {
            field: "creator_comm",
            source: CapturedBytesError::TooLong {
                length: 16,
                maximum: 15,
            },
        };
        assert_eq!(decode(&command), Err(command_error.clone()));
        assert_eq!(
            command_error.to_string(),
            "invalid captured bytes for creator_comm: captured byte length 16 exceeds the maximum 15"
        );
        assert_eq!(
            command_error.source().unwrap().to_string(),
            "captured byte length 16 exceeds the maximum 15"
        );

        let mut pathname = *FIXTURES[1];
        pathname[56..56 + PATH_SIZE].fill(0);
        pathname[56..61].copy_from_slice(b"short");
        pathname[44] = 1;
        assert_eq!(
            decode(&pathname),
            Err(DecodeError::CapturedBytes {
                field: "pathname",
                source: CapturedBytesError::OmissionRequiresFullCapacity {
                    length: 5,
                    capacity: 256,
                },
            })
        );
    }
}
