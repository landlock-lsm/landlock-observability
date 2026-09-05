// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Cow;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use unicode_general_category::{get_general_category, GeneralCategory};

mod private {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum OmissionPolicy {
        NotSupported,
        FullCapacity,
    }

    pub trait CapturedBytesOrigin {
        const ALLOWS_NUL: bool;
        const MAXIMUM_LEN: usize;
        const OMISSION_POLICY: OmissionPolicy;
        const DEBUG_NAME: &'static str;
        const DISPLAY_PREFIX: &'static str;
    }
}

/// A supported origin for bytes captured by the kernel.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait CapturedBytesOrigin: private::CapturedBytesOrigin {}

/// The origin marker for a captured filesystem pathname.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct PathnameOrigin;

impl private::CapturedBytesOrigin for PathnameOrigin {
    const ALLOWS_NUL: bool = false;
    const MAXIMUM_LEN: usize = 256;
    const OMISSION_POLICY: private::OmissionPolicy = private::OmissionPolicy::FullCapacity;
    const DEBUG_NAME: &'static str = "CapturedPath";
    const DISPLAY_PREFIX: &'static str = "";
}
impl CapturedBytesOrigin for PathnameOrigin {}

/// The origin marker for a captured task command.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct CommandOrigin;

impl private::CapturedBytesOrigin for CommandOrigin {
    const ALLOWS_NUL: bool = false;
    const MAXIMUM_LEN: usize = 15;
    const OMISSION_POLICY: private::OmissionPolicy = private::OmissionPolicy::NotSupported;
    const DEBUG_NAME: &'static str = "CapturedCommand";
    const DISPLAY_PREFIX: &'static str = "";
}
impl CapturedBytesOrigin for CommandOrigin {}

/// The origin marker for a captured abstract UNIX socket name.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct AbstractUnixSocketNameOrigin;

impl private::CapturedBytesOrigin for AbstractUnixSocketNameOrigin {
    const ALLOWS_NUL: bool = true;
    const MAXIMUM_LEN: usize = 107;
    const OMISSION_POLICY: private::OmissionPolicy = private::OmissionPolicy::NotSupported;
    const DEBUG_NAME: &'static str = "CapturedAbstractUnixSocketName";
    const DISPLAY_PREFIX: &'static str = "@";
}
impl CapturedBytesOrigin for AbstractUnixSocketNameOrigin {}

/// An error returned when captured bytes violate their origin's invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapturedBytesError {
    /// Path or command bytes contain a NUL byte.
    #[non_exhaustive]
    InteriorNul {
        /// The zero-based byte position of the NUL.
        position: usize,
    },
    /// The captured byte length exceeds the origin's maximum.
    #[non_exhaustive]
    TooLong {
        /// The rejected byte length.
        length: usize,
        /// The inclusive maximum byte length.
        maximum: usize,
    },
    /// The origin cannot represent omitted source bytes.
    OmissionNotSupported,
    /// Omission was reported without filling the capture capacity.
    #[non_exhaustive]
    OmissionRequiresFullCapacity {
        /// The rejected byte length.
        length: usize,
        /// The required capture capacity.
        capacity: usize,
    },
}

impl fmt::Display for CapturedBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul { position } => {
                write!(
                    formatter,
                    "captured bytes contain a NUL at position {position}"
                )
            }
            Self::TooLong { length, maximum } => write!(
                formatter,
                "captured byte length {length} exceeds the maximum {maximum}"
            ),
            Self::OmissionNotSupported => {
                formatter.write_str("this captured-byte origin cannot omit source bytes")
            }
            Self::OmissionRequiresFullCapacity { length, capacity } => write!(
                formatter,
                "omitted source bytes require a full {capacity}-byte capture, but length is {length}"
            ),
        }
    }
}

impl Error for CapturedBytesError {}

/// Bytes captured from a kernel source, with their origin tracked by `K`.
///
/// `bytes_omitted` records the precise producer state: it is true exactly when
/// source bytes existed beyond [`Self::as_bytes()`].
#[non_exhaustive]
pub struct CapturedBytes<K: CapturedBytesOrigin> {
    bytes: Vec<u8>,
    bytes_omitted: bool,
    origin: PhantomData<fn() -> K>,
}

impl<K: CapturedBytesOrigin> CapturedBytes<K> {
    /// Creates captured bytes and records whether source bytes were omitted.
    ///
    /// Path and command origins reject NUL. Abstract UNIX socket name bytes may
    /// contain NUL because their length, rather than a terminator, delimits them.
    pub fn new(bytes: Vec<u8>, bytes_omitted: bool) -> Result<Self, CapturedBytesError> {
        if !K::ALLOWS_NUL {
            if let Some(position) = bytes.iter().position(|byte| *byte == 0) {
                return Err(CapturedBytesError::InteriorNul { position });
            }
        }
        if bytes.len() > K::MAXIMUM_LEN {
            return Err(CapturedBytesError::TooLong {
                length: bytes.len(),
                maximum: K::MAXIMUM_LEN,
            });
        }
        if bytes_omitted {
            match K::OMISSION_POLICY {
                private::OmissionPolicy::NotSupported => {
                    return Err(CapturedBytesError::OmissionNotSupported);
                }
                private::OmissionPolicy::FullCapacity if bytes.len() != K::MAXIMUM_LEN => {
                    return Err(CapturedBytesError::OmissionRequiresFullCapacity {
                        length: bytes.len(),
                        capacity: K::MAXIMUM_LEN,
                    });
                }
                private::OmissionPolicy::FullCapacity => {}
            }
        }
        Ok(Self {
            bytes,
            bytes_omitted,
            origin: PhantomData,
        })
    }

    /// Returns the captured semantic bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns whether source bytes existed beyond the captured bytes.
    pub const fn bytes_omitted(&self) -> bool {
        self.bytes_omitted
    }

    /// Returns a lossy UTF-8 view without escaping hazardous bytes.
    ///
    /// # Warning
    ///
    /// **This method is not safe for direct display, logging, terminals,
    /// shells, or C-string APIs.** It does not escape NUL, control or format
    /// characters, terminal sequences, log separators, shell syntax, or other
    /// byte-oriented hazards. Use [`fmt::Display`] only for terminal or log
    /// output. Neither conversion performs shell quoting or C-string conversion.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }

    fn write_escaped(&self, formatter: &mut fmt::Formatter<'_>, omission: bool) -> fmt::Result {
        let mut remaining = self.bytes.as_slice();
        while !remaining.is_empty() {
            match std::str::from_utf8(remaining) {
                Ok(valid) => {
                    write_valid(formatter, valid)?;
                    remaining = &[];
                }
                Err(error) => {
                    let valid_end = error.valid_up_to();
                    write_valid(
                        formatter,
                        std::str::from_utf8(&remaining[..valid_end])
                            .expect("valid_up_to identifies valid UTF-8"),
                    )?;
                    let invalid_len = error.error_len().unwrap_or(remaining.len() - valid_end);
                    for byte in &remaining[valid_end..valid_end + invalid_len] {
                        write!(formatter, "\\x{byte:02x}")?;
                    }
                    remaining = &remaining[valid_end + invalid_len..];
                }
            }
        }
        if omission && self.bytes_omitted {
            formatter.write_str("…")?;
        }
        Ok(())
    }
}

impl CapturedBytes<PathnameOrigin> {
    /// Returns the raw captured pathname as a platform path.
    ///
    /// Unlike [`fmt::Display`], this view is not escaped.
    pub fn as_path(&self) -> &Path {
        Path::new(OsStr::from_bytes(&self.bytes))
    }
}

impl CapturedBytes<CommandOrigin> {
    /// Returns the raw captured command as a platform OS string.
    ///
    /// Unlike [`fmt::Display`], this view is not escaped.
    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.bytes)
    }
}

#[cfg(target_os = "linux")]
impl CapturedBytes<AbstractUnixSocketNameOrigin> {
    /// Constructs a native Linux socket address with the exact abstract name.
    ///
    /// # Errors
    ///
    /// Returns an error if the standard library rejects the name.
    pub fn to_socket_addr(&self) -> std::io::Result<std::os::unix::net::SocketAddr> {
        use std::os::linux::net::SocketAddrExt;

        std::os::unix::net::SocketAddr::from_abstract_name(&self.bytes)
    }
}

fn write_valid(formatter: &mut fmt::Formatter<'_>, valid: &str) -> fmt::Result {
    for character in valid.chars() {
        let unsafe_category = matches!(
            get_general_category(character),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
                | GeneralCategory::SpaceSeparator
        );
        if character == '\\' {
            formatter.write_str("\\\\")?;
        } else if character != ' ' && unsafe_category {
            write!(formatter, "\\u{{{:x}}}", u32::from(character))?;
        } else {
            write!(formatter, "{character}")?;
        }
    }
    Ok(())
}

impl<K: CapturedBytesOrigin> Clone for CapturedBytes<K> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            bytes_omitted: self.bytes_omitted,
            origin: PhantomData,
        }
    }
}

impl<K: CapturedBytesOrigin> PartialEq for CapturedBytes<K> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.bytes_omitted == other.bytes_omitted
    }
}
impl<K: CapturedBytesOrigin> Eq for CapturedBytes<K> {}

impl<K: CapturedBytesOrigin> Hash for CapturedBytes<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
        self.bytes_omitted.hash(state);
    }
}

impl<K: CapturedBytesOrigin> fmt::Display for CapturedBytes<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(K::DISPLAY_PREFIX)?;
        self.write_escaped(formatter, true)
    }
}

impl<K: CapturedBytesOrigin> fmt::Debug for CapturedBytes<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut escaped = format!("{self}");
        if self.bytes_omitted {
            escaped.pop();
        }
        formatter
            .debug_struct(K::DEBUG_NAME)
            .field("escaped", &escaped)
            .field("bytes_omitted", &self.bytes_omitted)
            .finish()
    }
}

/// Bytes captured from a filesystem pathname.
///
/// Values contain at most 256 NUL-free bytes.  Omission may be reported only
/// when all 256 bytes are present.
pub type CapturedPath = CapturedBytes<PathnameOrigin>;
/// Bytes captured from a task command name.
///
/// Values are complete and contain at most 15 NUL-free bytes.
pub type CapturedCommand = CapturedBytes<CommandOrigin>;
/// Exact length-delimited bytes of an abstract UNIX socket name.
///
/// Values are complete and contain at most 107 bytes.  The structural leading
/// namespace NUL is not included; embedded and trailing NUL bytes are preserved
/// and available through [`CapturedBytes::as_bytes`].
pub type CapturedAbstractUnixSocketName = CapturedBytes<AbstractUnixSocketNameOrigin>;

#[cfg(target_os = "linux")]
impl TryFrom<&CapturedAbstractUnixSocketName> for std::os::unix::net::SocketAddr {
    type Error = std::io::Error;

    fn try_from(name: &CapturedAbstractUnixSocketName) -> Result<Self, Self::Error> {
        name.to_socket_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_enforce_nul_invariants_and_views() {
        assert_eq!(
            CapturedPath::new(b"before\0after".to_vec(), false),
            Err(CapturedBytesError::InteriorNul { position: 6 })
        );
        assert_eq!(
            CapturedCommand::new(vec![0], false),
            Err(CapturedBytesError::InteriorNul { position: 0 })
        );
        let name = CapturedAbstractUnixSocketName::new(b"a\0b".to_vec(), false).unwrap();
        assert_eq!(name.as_bytes(), b"a\0b");

        let path = CapturedPath::new(b"/tmp/non-utf8-\xff".to_vec(), false).unwrap();
        assert_eq!(path.as_path().as_os_str().as_bytes(), path.as_bytes());
        let command = CapturedCommand::new(b"command-\xff".to_vec(), false).unwrap();
        assert_eq!(command.as_os_str().as_bytes(), command.as_bytes());
    }

    #[test]
    fn origins_enforce_length_and_omission_invariants() {
        assert_eq!(
            CapturedPath::new(vec![b'p'; 257], false),
            Err(CapturedBytesError::TooLong {
                length: 257,
                maximum: 256,
            })
        );
        assert_eq!(
            CapturedCommand::new(vec![b'c'; 16], false),
            Err(CapturedBytesError::TooLong {
                length: 16,
                maximum: 15,
            })
        );
        assert_eq!(
            CapturedAbstractUnixSocketName::new(vec![b'a'; 108], false),
            Err(CapturedBytesError::TooLong {
                length: 108,
                maximum: 107,
            })
        );
        assert_eq!(
            CapturedPath::new(b"short".to_vec(), true),
            Err(CapturedBytesError::OmissionRequiresFullCapacity {
                length: 5,
                capacity: 256,
            })
        );
        assert_eq!(
            CapturedCommand::new(b"command".to_vec(), true),
            Err(CapturedBytesError::OmissionNotSupported)
        );
        assert_eq!(
            CapturedAbstractUnixSocketName::new(b"socket".to_vec(), true),
            Err(CapturedBytesError::OmissionNotSupported)
        );

        for omitted in [false, true] {
            assert!(CapturedPath::new(vec![b'p'; 256], omitted).is_ok());
        }
        assert!(CapturedCommand::new(vec![b'c'; 15], false).is_ok());
        assert!(CapturedAbstractUnixSocketName::new(vec![b'a'; 107], false).is_ok());
        assert!(CapturedPath::new(Vec::new(), false).is_ok());
        assert!(CapturedCommand::new(Vec::new(), false).is_ok());
        assert!(CapturedAbstractUnixSocketName::new(Vec::new(), false).is_ok());
    }

    #[test]
    fn errors_identify_the_failed_check() {
        assert_eq!(
            CapturedBytesError::InteriorNul { position: 4 }.to_string(),
            "captured bytes contain a NUL at position 4"
        );
        assert_eq!(
            CapturedBytesError::TooLong {
                length: 16,
                maximum: 15,
            }
            .to_string(),
            "captured byte length 16 exceeds the maximum 15"
        );
        assert_eq!(
            CapturedBytesError::OmissionNotSupported.to_string(),
            "this captured-byte origin cannot omit source bytes"
        );
        assert_eq!(
            CapturedBytesError::OmissionRequiresFullCapacity {
                length: 5,
                capacity: 256,
            }
            .to_string(),
            "omitted source bytes require a full 256-byte capture, but length is 5"
        );
    }

    #[test]
    fn display_preserves_graphical_text_and_escapes_unsafe_data() {
        let value = CapturedAbstractUnixSocketName::new(
            "plain space/é界🙂\\\0\t\n\r\u{1b}\u{202e}\u{2066}\u{2028}\u{00a0}"
                .as_bytes()
                .iter()
                .copied()
                .chain([0xff])
                .collect(),
            false,
        )
        .unwrap();
        assert_eq!(
            value.to_string(),
            "@plain space/é界🙂\\\\\\u{0}\\u{9}\\u{a}\\u{d}\\u{1b}\\u{202e}\\u{2066}\\u{2028}\\u{a0}\\xff"
        );
    }

    #[test]
    fn omission_and_debug_are_explicit() {
        let complete = CapturedPath::new(b"path".to_vec(), false).unwrap();
        let omitted = CapturedPath::new(vec![b'p'; 256], true).unwrap();
        assert_eq!(complete.to_string(), "path");
        assert_eq!(omitted.to_string(), format!("{}…", "p".repeat(256)));
        assert_eq!(
            format!("{omitted:?}"),
            format!(
                "CapturedPath {{ escaped: \"{}\", bytes_omitted: true }}",
                "p".repeat(256)
            )
        );
        assert!(!complete.bytes_omitted());
        assert!(omitted.bytes_omitted());
    }

    #[test]
    fn lossy_conversion_remains_unescaped() {
        let value = CapturedAbstractUnixSocketName::new(b"a\0\n\xff".to_vec(), false).unwrap();
        assert_eq!(value.to_string_lossy(), "a\0\n�");
    }

    #[test]
    fn abstract_display_prefixes_empty_embedded_nul_and_invalid_utf8() {
        assert_eq!(
            CapturedAbstractUnixSocketName::new(Vec::new(), false)
                .unwrap()
                .to_string(),
            "@"
        );
        assert_eq!(
            CapturedAbstractUnixSocketName::new(b"a\0\xff".to_vec(), false)
                .unwrap()
                .to_string(),
            "@a\\u{0}\\xff"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_socket_addr_round_trips_empty_and_maximum_names() {
        use std::os::linux::net::SocketAddrExt;

        for name in [Vec::new(), (0_u8..=106).collect()] {
            let captured = CapturedAbstractUnixSocketName::new(name.clone(), false).unwrap();
            let address = captured.to_socket_addr().unwrap();
            assert_eq!(address.as_abstract_name(), Some(name.as_slice()));

            let converted = std::os::unix::net::SocketAddr::try_from(&captured).unwrap();
            assert_eq!(converted.as_abstract_name(), Some(name.as_slice()));
        }
    }
}
