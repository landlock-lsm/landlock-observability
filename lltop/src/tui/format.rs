// SPDX-License-Identifier: MIT OR Apache-2.0

use landlock_observability::event::{
    CapturedString, FilesystemAccess, KernelTimestamp, NetworkAccess, ScopeAccess,
};
use ratatui::text::Span;

pub(super) fn hex_id(value: u64) -> String {
    format!("{value:x}")
}

pub(super) fn ruleset(id: u64, version: Option<u32>) -> String {
    version.map_or_else(
        || format!("{}.?", hex_id(id)),
        |v| format!("{}.{v}", hex_id(id)),
    )
}

pub(super) fn escape(value: &CapturedString) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/') {
            escaped.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(escaped, "\\x{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    if value.is_truncated() {
        escaped.push('…');
    }
    escaped
}

fn access<'a>(names: impl Iterator<Item = &'a str>, unknown: u32) -> String {
    let mut parts = names.map(str::to_owned).collect::<Vec<_>>();
    if unknown != 0 {
        parts.push(format!("0x{unknown:x}"));
    }
    if parts.is_empty() {
        "0x0".to_owned()
    } else {
        parts.join(", ")
    }
}

pub(super) fn filesystem_rights(value: FilesystemAccess) -> String {
    access(
        value.known_names().map(|name| name.as_str()),
        value.unknown_bits(),
    )
}

pub(super) fn network_rights(value: NetworkAccess) -> String {
    access(
        value.known_names().map(|name| name.as_str()),
        value.unknown_bits(),
    )
}

pub(super) fn scope_rights(value: ScopeAccess) -> String {
    access(
        value.known_names().map(|name| name.as_str()),
        value.unknown_bits(),
    )
}

pub(super) fn filesystem(value: FilesystemAccess) -> String {
    format!("FS: {}", filesystem_rights(value))
}

pub(super) fn network(value: NetworkAccess) -> String {
    format!("Net: {}", network_rights(value))
}

pub(super) fn scope(value: ScopeAccess) -> String {
    format!("Scope: {}", scope_rights(value))
}

pub(super) fn timestamp(value: Option<KernelTimestamp>) -> String {
    value.map_or_else(|| "?".to_owned(), |v| format!("{}ns", v.as_nanoseconds()))
}

pub(super) fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}

pub(super) fn wrap(text: &str, first_width: usize, continuation_width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let mut remaining = text;
    let mut width = first_width.max(1);
    let mut output = Vec::new();
    while display_width(remaining) > width {
        let mut used_width = 0;
        let mut byte_limit = 0;
        for (index, character) in remaining.char_indices() {
            let mut encoded = [0; 4];
            let character_width = display_width(character.encode_utf8(&mut encoded));
            if used_width + character_width > width {
                if byte_limit == 0 {
                    byte_limit = index + character.len_utf8();
                }
                break;
            }
            used_width += character_width;
            byte_limit = index + character.len_utf8();
        }
        let candidate = &remaining[..byte_limit];
        let split = candidate
            .rfind(", ")
            .map(|index| index + 2)
            .or_else(|| candidate.rfind('/').map(|index| index + 1))
            .or_else(|| candidate.rfind(' ').map(|index| index + 1))
            .filter(|index| *index != 0)
            .unwrap_or(byte_limit);
        output.push(remaining[..split].to_owned());
        remaining = &remaining[split..];
        width = continuation_width.max(1);
    }
    output.push(remaining.to_owned());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_rights_support_prefixed_denials_and_unprefixed_fields() {
        let fs_access = FilesystemAccess::from_bits((1 << 2) | 0x8000_0000);
        let net_access = NetworkAccess::from_bits((1 << 1) | 0x8000_0000);
        let scoped = ScopeAccess::from_bits((1 << 1) | 0x8000_0000);

        assert_eq!(filesystem_rights(fs_access), "read_file, 0x80000000");
        assert_eq!(network_rights(net_access), "connect_tcp, 0x80000000");
        assert_eq!(scope_rights(scoped), "signal, 0x80000000");
        assert_eq!(filesystem(fs_access), "FS: read_file, 0x80000000");
        assert_eq!(network(net_access), "Net: connect_tcp, 0x80000000");
        assert_eq!(scope(scoped), "Scope: signal, 0x80000000");
    }

    #[test]
    fn escaping_blocks_terminal_control_and_marks_truncation() {
        let value = CapturedString::new(b"a b,\\\n\x1b\xff".to_vec(), true).unwrap();
        assert_eq!(escape(&value), "a\\x20b\\x2c\\x5c\\x0a\\x1b\\xff…");
    }

    #[test]
    fn wrapping_prefers_semantic_boundaries_and_is_utf8_safe() {
        assert_eq!(
            wrap("read_file, write_file", 12, 10),
            ["read_file, ", "write_file"]
        );
        assert_eq!(wrap("/long/path/name", 10, 8), ["/long/", "path/", "name"]);
        assert_eq!(wrap("éééé", 2, 2), ["éé", "éé"]);
        assert_eq!(wrap("界界", 2, 2), ["界", "界"]);
        assert_eq!(wrap("🔕x", 2, 2), ["🔕", "x"]);
        assert_eq!(wrap("🔔x", 2, 2), ["🔔", "x"]);
        assert_eq!(wrap("abcdef", 3, 2), ["abc", "de", "f"]);
    }
}
