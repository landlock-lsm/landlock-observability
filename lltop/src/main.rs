// SPDX-License-Identifier: MIT OR Apache-2.0

mod batch;
mod tui;

use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use batch::Batch;
use landlock_observability::collector::{
    Collector, CollectorReceiveErrorKind, ReceiveTimeoutError,
};

const RECEIVE_TIMEOUT: Duration = Duration::from_millis(100);
const READY_SIGNAL: &str = "LLTOP_READY";

enum Mode {
    Batch,
    Interactive,
}

fn parse_mode() -> Result<Mode, String> {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_default();
    match (args.next(), args.next()) {
        (None, None) => Ok(Mode::Interactive),
        (Some(argument), None) if argument == "--batch" => Ok(Mode::Batch),
        _ => Err(format!("usage: {} [--batch]", program.to_string_lossy())),
    }
}

fn run_batch(mut collector: Collector) -> Result<(), Box<dyn Error>> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{READY_SIGNAL}")?;
    stderr.flush()?;
    drop(stderr);

    let mut batch = Batch::new();
    let mut stdout = io::stdout().lock();
    loop {
        match collector.recv_timeout(RECEIVE_TIMEOUT) {
            Ok(event) => batch.process_and_write(&event, &mut stdout)?,
            Err(ReceiveTimeoutError::Timeout) => {}
            Err(ReceiveTimeoutError::Collector(error)) => match error.kind() {
                CollectorReceiveErrorKind::OutputQueueFull
                | CollectorReceiveErrorKind::MalformedSample => {
                    eprintln!("lltop: warning: {error}")
                }
                CollectorReceiveErrorKind::PollFailure | CollectorReceiveErrorKind::WorkerStop => {
                    return Err(Box::new(error))
                }
                _ => return Err(Box::new(error)),
            },
            Err(_) => return Err("unknown collector timeout error".into()),
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mode = parse_mode().map_err(io::Error::other)?;
    let collector = Collector::new()?;
    match mode {
        Mode::Batch => run_batch(collector),
        Mode::Interactive => tui::run(collector),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lltop: {error}");
        std::process::exit(1);
    }
}
