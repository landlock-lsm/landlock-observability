// SPDX-License-Identifier: MIT OR Apache-2.0

mod batch;
mod tui;

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use batch::Batch;
use landlock_observability::collector::{
    Collector, CollectorConfig, CollectorReceiveErrorKind, ReceiveTimeoutError,
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
                CollectorReceiveErrorKind::PollFailure
                | CollectorReceiveErrorKind::WorkerPanic
                | CollectorReceiveErrorKind::WorkerStop => return Err(Box::new(error)),
                _ => return Err(Box::new(error)),
            },
            Err(_) => return Err("unknown collector timeout error".into()),
        }
    }
}

fn join_worker(worker: JoinHandle<()>) -> Result<(), Box<dyn Error>> {
    worker.join().map_err(|payload| {
        // CollectorWorker::run() contains panics, so reaching this path means
        // its outer lifecycle failed. Do not inspect or drop an arbitrary
        // hostile panic payload.
        std::mem::forget(payload);
        Box::<dyn Error>::from(io::Error::other("collector worker thread panicked"))
    })
}

#[derive(Debug)]
struct ExecutionAndWorkerError {
    primary: Box<dyn Error>,
    worker: Box<dyn Error>,
}

impl fmt::Display for ExecutionAndWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "primary execution failure: {}; additional worker shutdown/join failure: {}",
            self.primary, self.worker
        )
    }
}

impl Error for ExecutionAndWorkerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

fn combine_execution_and_worker_results(
    primary: Result<(), Box<dyn Error>>,
    worker: Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    match (primary, worker) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(worker)) => Err(worker),
        (Err(primary), Err(worker)) => Err(Box::new(ExecutionAndWorkerError { primary, worker })),
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mode = parse_mode().map_err(io::Error::other)?;
    let (collector, collector_worker) = CollectorConfig::default().prepare()?;
    let worker = thread::Builder::new()
        .name("ll-observe".to_owned())
        .spawn(move || collector_worker.run())?;
    let result = match mode {
        Mode::Batch => run_batch(collector),
        Mode::Interactive => tui::run(collector),
    };
    let worker_result = join_worker(worker);
    combine_execution_and_worker_results(result, worker_result)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lltop: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestError(&'static str);

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for TestError {}

    fn failure(diagnosis: &'static str) -> Result<(), Box<dyn Error>> {
        Err(Box::new(TestError(diagnosis)))
    }

    #[test]
    fn combines_successful_results() {
        assert!(combine_execution_and_worker_results(Ok(()), Ok(())).is_ok());
    }

    #[test]
    fn preserves_primary_error() {
        let primary: Box<dyn Error> = Box::new(TestError("primary failure"));
        let primary_pointer = primary.downcast_ref::<TestError>().unwrap() as *const TestError;

        let error = combine_execution_and_worker_results(Err(primary), Ok(())).unwrap_err();
        let returned = error.downcast_ref::<TestError>().unwrap();

        assert_eq!(returned as *const TestError, primary_pointer);
        assert_eq!(returned.0, "primary failure");
    }

    #[test]
    fn preserves_worker_error() {
        let worker: Box<dyn Error> = Box::new(TestError("worker failure"));
        let worker_pointer = worker.downcast_ref::<TestError>().unwrap() as *const TestError;

        let error = combine_execution_and_worker_results(Ok(()), Err(worker)).unwrap_err();
        let returned = error.downcast_ref::<TestError>().unwrap();

        assert_eq!(returned as *const TestError, worker_pointer);
        assert_eq!(returned.0, "worker failure");
    }

    #[test]
    fn reports_both_errors_with_primary_source() {
        let error = combine_execution_and_worker_results(
            failure("primary failure"),
            failure("worker failure"),
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "primary execution failure: primary failure; additional worker shutdown/join failure: worker failure"
        );
        let source = error.source().unwrap().downcast_ref::<TestError>().unwrap();
        assert_eq!(source.0, "primary failure");
    }
}
