// SPDX-License-Identifier: MIT OR Apache-2.0

use std::error::Error;
use std::fmt;

use crate::event::{
    AddRuleFsEvent, AddRuleNetEvent, CapturedString, CreateDomainEvent, CreateRulesetEvent,
    DenialContext, DenyAccessFsEvent, DenyAccessNetEvent, DenyPtraceEvent,
    DenyScopeAbstractUnixSocketEvent, DenyScopeSignalEvent, DomainId, DomainMembership,
    EnforceDomainEvent, Event, FilesystemAccess, FreeDomainEvent, FreeRulesetEvent,
    HierarchySnapshot, KernelTimestamp, NetworkAccess, RulesetId, ScopeAccess, UnknownEvent,
};

const RECORD_SIZE: usize = 344;
const TIMESTAMP_OFFSET: usize = 0;
const TYPE_OFFSET: usize = 8;
const UNION_OFFSET: usize = 16;
const COMM_SIZE: usize = 16;
const PATH_SIZE: usize = 256;

const CREATE_RULESET: u8 = 1;
const ADD_RULE_FS: u8 = 2;
const ADD_RULE_NET: u8 = 3;
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
            Self::Field { field } => write!(formatter, "invalid field {field}"),
        }
    }
}

impl Error for DecodeError {}

fn bytes<const N: usize>(
    data: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; N], DecodeError> {
    data.get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(DecodeError::Field { field })
}

fn u32_at(data: &[u8], offset: usize, field: &'static str) -> Result<u32, DecodeError> {
    Ok(u32::from_ne_bytes(bytes(data, offset, field)?))
}

fn u64_at(data: &[u8], offset: usize, field: &'static str) -> Result<u64, DecodeError> {
    Ok(u64::from_ne_bytes(bytes(data, offset, field)?))
}

fn string_at(
    data: &[u8],
    offset: usize,
    size: usize,
    field: &'static str,
) -> Result<CapturedString, DecodeError> {
    let value = data
        .get(offset..offset + size)
        .ok_or(DecodeError::Field { field })?;
    Ok(CapturedString::from_fixed(value))
}

fn boolean_at(data: &[u8], offset: usize, field: &'static str) -> Result<bool, DecodeError> {
    let value = *data.get(offset).ok_or(DecodeError::Field { field })?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::Boolean { field, value }),
    }
}

fn parent(value: u64) -> Option<DomainId> {
    (value != 0).then(|| DomainId::new(value))
}

fn domain_membership(value: u64) -> DomainMembership {
    if value == 0 {
        DomainMembership::Unsandboxed
    } else {
        DomainMembership::Sandboxed(DomainId::new(value))
    }
}

fn denial_context(data: &[u8]) -> Result<DenialContext, DecodeError> {
    Ok(DenialContext::new(
        HierarchySnapshot::new(
            DomainId::new(u64_at(data, UNION_OFFSET, "domain_id")?),
            parent(u64_at(data, 24, "parent_id")?),
            u32_at(data, 32, "creator_tgid")?,
            string_at(data, 36, COMM_SIZE, "creator_comm")?,
        ),
        u64_at(data, 56, "cumulative_denial_count")?,
        boolean_at(data, 68, "same_exec")?,
        boolean_at(data, 69, "logged")?,
    ))
}

/// Decodes one complete private producer record into a semantic event.
pub(crate) fn decode(data: &[u8]) -> Result<Event, DecodeError> {
    if data.len() != RECORD_SIZE {
        return Err(DecodeError::Length {
            expected: RECORD_SIZE,
            actual: data.len(),
        });
    }

    let event_type = data[TYPE_OFFSET];
    let timestamp = KernelTimestamp::from_nanoseconds(u64_at(data, TIMESTAMP_OFFSET, "timestamp")?);

    let event = match event_type {
        CREATE_RULESET => Event::CreateRuleset(CreateRulesetEvent::new(
            timestamp,
            RulesetId::new(u64_at(data, 16, "ruleset_id")?),
            u32_at(data, 24, "ruleset_version")?,
            FilesystemAccess::from_bits(u32_at(data, 28, "handled_fs")?),
            NetworkAccess::from_bits(u32_at(data, 32, "handled_net")?),
            ScopeAccess::from_bits(u32_at(data, 36, "scoped")?),
        )),
        ADD_RULE_FS => Event::AddRuleFs(AddRuleFsEvent::new(
            timestamp,
            RulesetId::new(u64_at(data, 16, "ruleset_id")?),
            u32_at(data, 24, "ruleset_version")?,
            FilesystemAccess::from_bits(u32_at(data, 28, "access_rights")?),
            u32_at(data, 32, "device")?,
            u64_at(data, 40, "inode")?,
            string_at(data, 48, PATH_SIZE, "pathname")?,
        )),
        ADD_RULE_NET => Event::AddRuleNet(AddRuleNetEvent::new(
            timestamp,
            RulesetId::new(u64_at(data, 16, "ruleset_id")?),
            u32_at(data, 24, "ruleset_version")?,
            NetworkAccess::from_bits(u32_at(data, 28, "access_rights")?),
            u64_at(data, 32, "port")?,
        )),
        CREATE_DOMAIN => Event::CreateDomain(CreateDomainEvent::new(
            timestamp,
            RulesetId::new(u64_at(data, 16, "ruleset_id")?),
            u32_at(data, 24, "ruleset_version")?,
            DomainId::new(u64_at(data, 32, "domain_id")?),
            parent(u64_at(data, 40, "parent_id")?),
            u32_at(data, 48, "creator_tgid")?,
            string_at(data, 52, COMM_SIZE, "creator_comm")?,
        )),
        DENY_ACCESS_FS => Event::DenyAccessFs(DenyAccessFsEvent::new(
            timestamp,
            denial_context(data)?,
            FilesystemAccess::from_bits(u32_at(data, 64, "blockers")?),
            u32_at(data, 72, "device")?,
            u64_at(data, 80, "inode")?,
            string_at(data, 88, PATH_SIZE, "pathname")?,
        )),
        DENY_ACCESS_NET => Event::DenyAccessNet(DenyAccessNetEvent::new(
            timestamp,
            denial_context(data)?,
            NetworkAccess::from_bits(u32_at(data, 64, "blockers")?),
            u64_at(data, 72, "source_port")?,
            u64_at(data, 80, "destination_port")?,
        )),
        DENY_PTRACE => Event::DenyPtrace(DenyPtraceEvent::new(
            timestamp,
            denial_context(data)?,
            domain_membership(u64_at(data, 72, "tracee_domain")?),
            u32_at(data, 80, "tracee_pid")?,
            string_at(data, 84, COMM_SIZE, "tracee_comm")?,
        )),
        DENY_SCOPE_SIGNAL => Event::DenyScopeSignal(DenyScopeSignalEvent::new(
            timestamp,
            denial_context(data)?,
            domain_membership(u64_at(data, 72, "target_domain")?),
            u32_at(data, 80, "target_pid")?,
            string_at(data, 84, COMM_SIZE, "target_comm")?,
        )),
        DENY_SCOPE_ABSTRACT_UNIX_SOCKET => {
            Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
                timestamp,
                denial_context(data)?,
                domain_membership(u64_at(data, 72, "peer_domain")?),
                u32_at(data, 80, "peer_pid")?,
            ))
        }
        FREE_DOMAIN => Event::FreeDomain(FreeDomainEvent::new(
            timestamp,
            DomainId::new(u64_at(data, 16, "domain_id")?),
            u64_at(data, 24, "denial_count")?,
        )),
        FREE_RULESET => Event::FreeRuleset(FreeRulesetEvent::new(
            timestamp,
            RulesetId::new(u64_at(data, 16, "ruleset_id")?),
            u32_at(data, 24, "ruleset_version")?,
        )),
        ENFORCE_DOMAIN => Event::EnforceDomain(EnforceDomainEvent::new(
            timestamp,
            DomainId::new(u64_at(data, 16, "domain_id")?),
            u32_at(data, 24, "enforcing_tid")?,
            boolean_at(data, 28, "complete")?,
            boolean_at(data, 29, "process_wide")?,
            boolean_at(data, 30, "no_new_privs")?,
        )),
        _ => Event::Unknown(UnknownEvent::new(timestamp, event_type, data.len())),
    };
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn captured(bytes: impl AsRef<[u8]>, truncated: bool) -> CapturedString {
        CapturedString::new(bytes.as_ref().to_vec(), truncated).unwrap()
    }

    fn context(
        domain_id: u64,
        parent_id: Option<u64>,
        creator_tgid: u32,
        creator_comm: CapturedString,
        cumulative_denial_count: u64,
        same_exec: bool,
        logged: bool,
    ) -> DenialContext {
        DenialContext::new(
            HierarchySnapshot::new(
                DomainId::new(domain_id),
                parent_id.map(DomainId::new),
                creator_tgid,
                creator_comm,
            ),
            cumulative_denial_count,
            same_exec,
            logged,
        )
    }

    #[test]
    fn decodes_all_fixture_fields() {
        let expected = [
            Event::CreateRuleset(CreateRulesetEvent::new(
                KernelTimestamp::from_nanoseconds(0x1100000000000001),
                RulesetId::new(0xA100000000000001),
                0x12000001,
                FilesystemAccess::from_bits(0x80010005),
                NetworkAccess::from_bits(0x8000000A),
                ScopeAccess::from_bits(0x80000003),
            )),
            Event::AddRuleFs(AddRuleFsEvent::new(
                KernelTimestamp::from_nanoseconds(0x2200000000000002),
                RulesetId::new(0xA200000000000002),
                0x23000002,
                FilesystemAccess::from_bits(0x80004006),
                0x34000002,
                0x4500000000000002,
                captured(b"/fixture/\xff\x1b", false),
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                KernelTimestamp::from_nanoseconds(0x3300000000000003),
                RulesetId::new(0xA300000000000003),
                0x34000003,
                NetworkAccess::from_bits(0x80000009),
                0x5600000000000003,
            )),
            Event::CreateDomain(CreateDomainEvent::new(
                KernelTimestamp::from_nanoseconds(0x4400000000000004),
                RulesetId::new(0xA400000000000004),
                0x45000004,
                DomainId::new(0xD400000000000004),
                None,
                0x56000004,
                captured(b"sixteen-byte-cmd", true),
            )),
            Event::DenyAccessFs(DenyAccessFsEvent::new(
                KernelTimestamp::from_nanoseconds(0x5500000000000005),
                context(
                    0xD000000000000005,
                    None,
                    0x51000005,
                    captured(b"creator-5", false),
                    0xC100000000000005,
                    true,
                    false,
                ),
                FilesystemAccess::from_bits(0x80010005),
                0x72000005,
                0x8300000000000005,
                captured(vec![b'P'; 256], true),
            )),
            Event::DenyAccessNet(DenyAccessNetEvent::new(
                KernelTimestamp::from_nanoseconds(0x6600000000000006),
                context(
                    0xD000000000000006,
                    Some(0xA000000000000006),
                    0x51000006,
                    captured(b"creator-6", false),
                    0xC100000000000006,
                    false,
                    true,
                ),
                NetworkAccess::from_bits(0x80010006),
                0x7400000000000006,
                0x8500000000000006,
            )),
            Event::DenyPtrace(DenyPtraceEvent::new(
                KernelTimestamp::from_nanoseconds(0x7700000000000007),
                context(
                    0xD000000000000007,
                    Some(0xA000000000000007),
                    0x51000007,
                    captured(b"creator-7", false),
                    0xC100000000000007,
                    true,
                    true,
                ),
                DomainMembership::Unsandboxed,
                0x86000007,
                captured(b"ptrace-target", false),
            )),
            Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                KernelTimestamp::from_nanoseconds(0x8800000000000008),
                context(
                    0xD000000000000008,
                    Some(0xA000000000000008),
                    0x51000008,
                    captured(b"creator-8", false),
                    0xC100000000000008,
                    false,
                    false,
                ),
                DomainMembership::Sandboxed(DomainId::new(0xE800000000000008)),
                0x97000008,
                captured(b"signal-target", false),
            )),
            Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
                KernelTimestamp::from_nanoseconds(0x9900000000000009),
                context(
                    0xD000000000000009,
                    Some(0xA000000000000009),
                    0x51000009,
                    captured(b"sixteen-byte-cmd", true),
                    0xC100000000000009,
                    true,
                    false,
                ),
                DomainMembership::Sandboxed(DomainId::new(0xE900000000000009)),
                0xA8000009,
            )),
            Event::FreeDomain(FreeDomainEvent::new(
                KernelTimestamp::from_nanoseconds(0xAA0000000000000A),
                DomainId::new(0xDA0000000000000A),
                0xAB0000000000000A,
            )),
            Event::FreeRuleset(FreeRulesetEvent::new(
                KernelTimestamp::from_nanoseconds(0xBB0000000000000B),
                RulesetId::new(0xAB0000000000000B),
                0xBC00000B,
            )),
            Event::EnforceDomain(EnforceDomainEvent::new(
                KernelTimestamp::from_nanoseconds(0xCC0000000000000C),
                DomainId::new(0xDC0000000000000C),
                0xCD00000C,
                true,
                false,
                true,
            )),
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
        assert_eq!(value.hierarchy().domain_id(), DomainId::new(domain_id));
        assert_eq!(value.hierarchy().parent_id(), parent_id.map(DomainId::new));
        assert_eq!(value.hierarchy().creator_tgid(), creator_tgid);
        assert_eq!(value.hierarchy().creator_comm().as_bytes(), creator_comm.0);
        assert_eq!(
            value.hierarchy().creator_comm().is_truncated(),
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
        assert_eq!(value.ruleset_id(), RulesetId::new(0xA100000000000001));
        assert_eq!(value.ruleset_version(), 0x12000001);
        assert_eq!(value.handled_fs().bits(), 0x80010005);
        assert_eq!(value.handled_net().bits(), 0x8000000A);
        assert_eq!(value.scoped().bits(), 0x80000003);

        let Event::AddRuleFs(value) = decode(FIXTURES[1]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x2200000000000002);
        assert_eq!(value.ruleset_id(), RulesetId::new(0xA200000000000002));
        assert_eq!(value.ruleset_version(), 0x23000002);
        assert_eq!(value.access_rights().bits(), 0x80004006);
        assert_eq!(value.device(), 0x34000002);
        assert_eq!(value.inode(), 0x4500000000000002);
        assert_eq!(value.pathname().as_bytes(), b"/fixture/\xff\x1b");

        let Event::AddRuleNet(value) = decode(FIXTURES[2]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x3300000000000003);
        assert_eq!(value.ruleset_id(), RulesetId::new(0xA300000000000003));
        assert_eq!(value.ruleset_version(), 0x34000003);
        assert_eq!(value.access_rights().bits(), 0x80000009);
        assert_eq!(value.port(), 0x5600000000000003);

        let Event::CreateDomain(value) = decode(FIXTURES[3]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0x4400000000000004);
        assert_eq!(value.ruleset_id(), RulesetId::new(0xA400000000000004));
        assert_eq!(value.ruleset_version(), 0x45000004);
        assert_eq!(value.domain_id(), DomainId::new(0xD400000000000004));
        assert_eq!(value.parent_id(), None);
        assert_eq!(value.creator_tgid(), 0x56000004);
        assert_eq!(value.creator_comm().as_bytes(), b"sixteen-byte-cmd");

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
        assert_eq!(value.blockers().bits(), 0x80010005);
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
        assert_eq!(value.blockers().bits(), 0x80010006);
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
        assert_eq!(value.tracee_pid(), 0x86000007);
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
            DomainMembership::Sandboxed(DomainId::new(0xE800000000000008))
        );
        assert_eq!(value.target_pid(), 0x97000008);
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
            (b"sixteen-byte-cmd", true),
            0xC100000000000009,
            (true, false),
        );
        assert_eq!(
            value.peer_domain(),
            DomainMembership::Sandboxed(DomainId::new(0xE900000000000009))
        );
        assert_eq!(value.peer_pid(), 0xA8000009);

        let Event::FreeDomain(value) = decode(FIXTURES[9]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xAA0000000000000A);
        assert_eq!(value.domain_id(), DomainId::new(0xDA0000000000000A));
        assert_eq!(value.denial_count(), 0xAB0000000000000A);

        let Event::FreeRuleset(value) = decode(FIXTURES[10]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xBB0000000000000B);
        assert_eq!(value.ruleset_id(), RulesetId::new(0xAB0000000000000B));
        assert_eq!(value.ruleset_version(), 0xBC00000B);

        let Event::EnforceDomain(value) = decode(FIXTURES[11]).unwrap() else {
            panic!()
        };
        assert_eq!(value.timestamp().as_nanoseconds(), 0xCC0000000000000C);
        assert_eq!(value.domain_id(), DomainId::new(0xDC0000000000000C));
        assert_eq!(value.enforcing_tid(), 0xCD00000C);
        assert!(value.complete());
        assert!(!value.process_wide());
        assert!(value.no_new_privs());
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
    fn preserves_unknown_kind_facts() {
        let mut data = *FIXTURES[0];
        data[TYPE_OFFSET] = 0xF3;
        let event = decode(&data).unwrap();
        assert_eq!(
            event.timestamp(),
            KernelTimestamp::from_nanoseconds(0x1100000000000001)
        );
        assert_eq!(
            event,
            Event::Unknown(UnknownEvent::new(
                KernelTimestamp::from_nanoseconds(0x1100000000000001),
                0xF3,
                RECORD_SIZE
            ))
        );
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
            DecodeError::Field {
                field: "semantic_field"
            }
            .to_string(),
            "invalid field semantic_field"
        );
    }

    #[test]
    fn rejects_every_invalid_boolean_value() {
        for (fixture, offset, field) in [
            (4, 68, "same_exec"),
            (4, 69, "logged"),
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
        let Event::AddRuleFs(event) = decode(FIXTURES[1]).unwrap() else {
            panic!()
        };
        assert_eq!(event.pathname().as_bytes(), b"/fixture/\xff\x1b");
        assert!(!event.pathname().is_truncated());
        assert_eq!(event.pathname().to_string_lossy(), "/fixture/�\u{1b}");
        let Event::CreateDomain(event) = decode(FIXTURES[3]).unwrap() else {
            panic!()
        };
        assert_eq!(event.creator_comm().as_bytes(), b"sixteen-byte-cmd");
        assert!(event.creator_comm().is_truncated());
    }
}
