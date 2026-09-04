// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, stdout, Write};

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};

/// Restores every terminal mode acquired during construction, including unwind.
pub(super) struct TerminalSession {
    raw: bool,
    alternate: bool,
    mouse: bool,
}

impl TerminalSession {
    pub(super) fn enter() -> io::Result<Self> {
        let mut session = Self {
            raw: false,
            alternate: false,
            mouse: false,
        };
        enable_raw_mode()?;
        session.raw = true;
        // Writing the sequence can succeed before a later flush reports failure.
        session.alternate = true;
        execute!(stdout(), EnterAlternateScreen)?;
        // Mouse setup observes only local write and flush errors.
        let _ = session.enable_mouse(stdout());
        Ok(session)
    }

    fn enable_mouse<W: Write>(&mut self, mut writer: W) -> io::Result<()> {
        self.mouse = true;
        execute!(writer, EnableMouseCapture)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if self.mouse {
            let _ = execute!(stdout(), DisableMouseCapture);
        }
        if self.alternate {
            let _ = execute!(stdout(), LeaveAlternateScreen);
        }
        if self.raw {
            let _ = disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FlushFailure {
        written: Vec<u8>,
    }

    impl Write for FlushFailure {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    #[test]
    fn mouse_cleanup_stays_armed_after_flush_failure() {
        let mut session = TerminalSession {
            raw: false,
            alternate: false,
            mouse: false,
        };
        let mut writer = FlushFailure::default();

        let result = session.enable_mouse(&mut writer);

        assert!(session.mouse);
        session.mouse = false;
        assert_eq!(
            writer.written,
            b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1015h\x1b[?1006h"
        );
        assert!(result.is_err());
    }
}
