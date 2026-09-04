// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use landlock::{AccessFs, Ruleset, RulesetAttr, Scope};
use tempfile::TempDir;
use wait_timeout::ChildExt;

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stream {
    Stdout,
    Stderr,
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn finish(&mut self) -> Result<ExitStatus, Box<dyn Error>> {
        if let Some(status) = self.child.wait_timeout(DEADLINE)? {
            return Ok(status);
        }
        let _ = self.child.kill();
        let status = self.child.wait()?;
        Err(format!(
            "child {} missed its deadline and exited with {status}",
            self.child.id()
        )
        .into())
    }

    fn terminate(&mut self) -> Result<(), Box<dyn Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.finish()?;
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait_timeout(DEADLINE);
        let _ = self.child.try_wait();
    }
}

struct Monitor {
    child: ChildGuard,
    lines: Receiver<(Stream, io::Result<String>)>,
    readers: Vec<JoinHandle<()>>,
    stderr: Vec<String>,
}

impl Monitor {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let child = Command::new(env!("CARGO_BIN_EXE_lltop"))
            .arg("--batch")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut child = ChildGuard::new(child);
        let stdout = child
            .child
            .stdout
            .take()
            .ok_or("lltop stdout was not piped")?;
        let stderr = child
            .child
            .stderr
            .take()
            .ok_or("lltop stderr was not piped")?;
        let (sender, lines) = mpsc::channel();
        let readers = vec![
            drain_lines(Stream::Stdout, stdout, sender.clone()),
            drain_lines(Stream::Stderr, stderr, sender),
        ];
        Ok(Self {
            child,
            lines,
            readers,
            stderr: Vec::new(),
        })
    }

    fn wait_ready(&mut self) -> Result<(), Box<dyn Error>> {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let (stream, line) = self.recv_before(deadline)?;
            let line = line?;
            match stream {
                Stream::Stderr if line == "LLTOP_READY" => return Ok(()),
                Stream::Stderr => self.stderr.push(line),
                Stream::Stdout => {
                    return Err(format!("lltop emitted stdout before readiness: {line:?}").into())
                }
            }
        }
    }

    fn recv_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(Stream, io::Result<String>), Box<dyn Error>> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("deadline expired")?;
        Ok(self.lines.recv_timeout(remaining)?)
    }

    fn finish(mut self) -> Result<Vec<String>, Box<dyn Error>> {
        let unexpected_status = self.child.child.try_wait()?;
        if unexpected_status.is_none() {
            self.child.terminate()?;
        }
        for reader in self.readers.drain(..) {
            reader.join().map_err(|_| "lltop output reader panicked")?;
        }
        for (stream, line) in self.lines.try_iter() {
            let line = line?;
            match stream {
                Stream::Stdout => {
                    parse_record(&line)?;
                }
                Stream::Stderr => self.stderr.push(line),
            }
        }
        if let Some(status) = unexpected_status {
            return Err(format!("lltop exited unexpectedly with {status}").into());
        }
        if self
            .stderr
            .iter()
            .any(|line| line.starts_with("lltop: ") || line.contains("panicked at"))
        {
            return Err(format!("lltop reported an error: {:#?}", self.stderr).into());
        }
        Ok(std::mem::take(&mut self.stderr))
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        if self.readers.is_empty() {
            return;
        }
        let _ = self.child.terminate();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn drain_lines<R: Read + Send + 'static>(
    stream: Stream,
    input: R,
    sender: mpsc::Sender<(Stream, io::Result<String>)>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(input).lines() {
            let failed = line.is_err();
            if sender.send((stream, line)).is_err() || failed {
                break;
            }
        }
    })
}

struct Target {
    child: ChildGuard,
    input: Option<ChildStdin>,
    reader: Option<JoinHandle<io::Result<()>>>,
}

impl Target {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let child = Command::new(env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("batch_integration")
            .arg("--nocapture")
            .env("LLTOP_TEST_MODE", "target")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut child = ChildGuard::new(child);
        let input = child
            .child
            .stdin
            .take()
            .ok_or("target stdin was not piped")?;
        let output = child
            .child
            .stdout
            .take()
            .ok_or("target stdout was not piped")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = BufReader::new(output);
            let ready = loop {
                let mut line = String::new();
                match output.read_line(&mut line) {
                    Ok(0) => break Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    Ok(_) if line.trim_end() == "TARGET_READY" => break Ok(()),
                    Ok(_) => {}
                    Err(error) => break Err(error),
                }
            };
            let _ = sender.send(ready);
            io::copy(&mut output, &mut io::sink()).map(|_| ())
        });
        match receiver.recv_timeout(DEADLINE) {
            Ok(Ok(())) => Ok(Self {
                child,
                input: Some(input),
                reader: Some(reader),
            }),
            Ok(Err(error)) => {
                let _ = child.terminate();
                let _ = reader.join();
                Err(error.into())
            }
            Err(error) => {
                let _ = child.terminate();
                let _ = reader.join();
                Err(error.into())
            }
        }
    }

    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        drop(self.input.take());
        let status = self.child.finish()?;
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| "target reader panicked")??;
        }
        if !status.success() {
            return Err(format!("target exited with {status}").into());
        }
        Ok(())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        drop(self.input.take());
        if let Some(reader) = self.reader.take() {
            let _ = self.child.terminate();
            let _ = reader.join();
        }
    }
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn escaped_hex(value: &str) -> Result<String, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has odd length".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let mut escaped = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("\\x{byte:02x}"));
        }
    }
    Ok(escaped)
}

fn target_helper() -> Result<(), Box<dyn Error>> {
    println!("TARGET_READY");
    io::stdout().flush()?;
    io::stdin().read_to_end(&mut Vec::new())?;
    Ok(())
}

fn scenario_helper() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let duplicate = temp.path().join("duplicate");
    let distinct = temp.path().join("distinct");
    fs::write(&duplicate, b"duplicate")?;
    fs::write(&distinct, b"distinct")?;
    let mut target = Target::spawn()?;
    let target_pid = target.child.id();

    let status = Ruleset::default()
        .handle_access(AccessFs::ReadFile)?
        .scope(Scope::Signal)?
        .create()?
        .restrict_self()?;
    if status.ruleset != landlock::RulesetStatus::FullyEnforced {
        return Err(format!("ruleset was not fully enforced: {status:?}").into());
    }

    for path in [&duplicate, &duplicate, &distinct] {
        let error = fs::read(path).unwrap_err();
        if error.kind() != io::ErrorKind::PermissionDenied {
            return Err(format!("unexpected filesystem denial for {path:?}: {error}").into());
        }
    }
    let error = target.child.child.kill().unwrap_err();
    if error.kind() != io::ErrorKind::PermissionDenied {
        return Err(format!("unexpected signal denial: {error}").into());
    }

    println!(
        "SCENARIO duplicate={} distinct={} target={target_pid}",
        encode_hex(duplicate.as_os_str().as_bytes()),
        encode_hex(distinct.as_os_str().as_bytes())
    );
    io::stdout().flush()?;
    target.finish()?;
    Ok(())
}

fn run_scenario() -> Result<(u32, HashMap<String, String>), Box<dyn Error>> {
    let child = Command::new(env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg("batch_integration")
        .arg("--nocapture")
        .env("LLTOP_TEST_MODE", "scenario")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child = ChildGuard::new(child);
    let pid = child.id();
    let output = child
        .child
        .stdout
        .take()
        .ok_or("scenario stdout was not piped")?;
    let reader = thread::spawn(move || -> io::Result<Option<String>> {
        let mut result = None;
        for line in BufReader::new(output).lines() {
            let line = line?;
            if line.starts_with("SCENARIO ") {
                result = Some(line);
            }
        }
        Ok(result)
    });
    let status = child.finish();
    let line = reader
        .join()
        .map_err(|_| "scenario output reader panicked")??
        .ok_or("scenario did not report its result")?;
    let status = status?;
    if !status.success() {
        return Err(format!("scenario exited with {status}").into());
    }
    Ok((pid, named_fields(&line)?))
}

#[derive(Clone, Debug)]
struct Record {
    kind: String,
    fields: HashMap<String, String>,
}

fn named_fields(line: &str) -> Result<HashMap<String, String>, Box<dyn Error>> {
    named_fields_for_record(line, false)
}

fn named_fields_for_record(
    line: &str,
    stats: bool,
) -> Result<HashMap<String, String>, Box<dyn Error>> {
    let mut fields = HashMap::new();
    for field in line.split_whitespace().skip(1) {
        let field = if stats {
            field.trim_matches(|byte| byte == '(' || byte == ')')
        } else {
            field
        };
        let (name, value) = field
            .split_once('=')
            .ok_or_else(|| format!("field is not named in {line:?}: {field:?}"))?;
        if name.is_empty() || value.is_empty() {
            return Err(format!("incomplete field in {line:?}: {field:?}").into());
        }
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate field in {line:?}: {name:?}").into());
        }
    }
    Ok(fields)
}

fn parse_record(line: &str) -> Result<Record, Box<dyn Error>> {
    let kind = line.split_whitespace().next().ok_or("empty lltop record")?;
    let fields = named_fields_for_record(line, kind == "STATS")?;
    let required: &[&str] = match kind {
        "DOMAIN" => &["domain", "parent", "ruleset", "creator"],
        "DROP_RULESET" => &["ruleset"],
        "DENIAL" => &[
            "type",
            "domain",
            "blockers",
            "target",
            "count",
            "age",
            "same_exec",
            "logged",
        ],
        "STATS" => &[
            "domains",
            "denials",
            "fs",
            "net",
            "ptrace",
            "signal",
            "abstract_unix",
        ],
        _ => return Err(format!("unknown lltop record type: {line:?}").into()),
    };
    for name in required {
        if !fields.contains_key(*name) {
            return Err(format!("missing {name} in {line:?}").into());
        }
    }
    if kind == "DENIAL" {
        let relational_fields = [
            "other_domain",
            "tracee_domain",
            "target_domain",
            "peer_domain",
        ];
        let expected = match fields.get("type").map(String::as_str) {
            Some("PTRACE") => Some("tracee_domain"),
            Some("SIGNAL") => Some("target_domain"),
            Some("ABSTRACT_UNIX") => Some("peer_domain"),
            _ => None,
        };
        if relational_fields
            .iter()
            .any(|name| fields.contains_key(*name) != (expected == Some(*name)))
        {
            return Err(format!("invalid relational fields in {line:?}").into());
        }
    }
    Ok(Record {
        kind: kind.to_owned(),
        fields,
    })
}

fn decimal(record: &Record, name: &str) -> Result<u64, Box<dyn Error>> {
    Ok(record.fields.get(name).ok_or(name.to_owned())?.parse()?)
}

fn assert_stats(record: &Record) -> Result<(), Box<dyn Error>> {
    let total = decimal(record, "denials")?;
    let sum = record
        .fields
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "domains" | "denials"))
        .try_fold(0_u64, |sum, (_, value)| {
            Ok::<_, Box<dyn Error>>(sum + value.parse::<u64>()?)
        })?;
    if total != sum {
        return Err(format!("inconsistent statistics: {record:?}").into());
    }
    let domains = record.fields.get("domains").ok_or("missing domains")?;
    let (allocated, all) = domains.split_once('/').ok_or("invalid domain counts")?;
    if allocated.parse::<u64>()? > all.parse::<u64>()? {
        return Err(format!("invalid domain statistics: {record:?}").into());
    }
    Ok(())
}

fn allocated_domains(record: &Record) -> Result<u64, Box<dyn Error>> {
    Ok(record
        .fields
        .get("domains")
        .ok_or("missing domains")?
        .split_once('/')
        .ok_or("invalid domain counts")?
        .0
        .parse()?)
}

fn is_domain_deallocation(previous: &Record, current: &Record) -> Result<bool, Box<dyn Error>> {
    if allocated_domains(previous)? != allocated_domains(current)?.saturating_add(1)
        || previous.fields.get("denials") != current.fields.get("denials")
    {
        return Ok(false);
    }
    Ok(previous
        .fields
        .iter()
        .all(|(name, value)| name == "domains" || current.fields.get(name) == Some(value)))
}

fn assert_stats_transition(
    previous: &Record,
    current: &Record,
    changed_kind: &str,
) -> Result<(), Box<dyn Error>> {
    assert_stats(current)?;
    if decimal(current, "denials")? != decimal(previous, "denials")? + 1 {
        return Err(
            format!("invalid total statistics transition: {previous:?} -> {current:?}").into(),
        );
    }
    for (name, value) in &previous.fields {
        if matches!(name.as_str(), "domains" | "denials") {
            continue;
        }
        let expected = value.parse::<u64>()? + u64::from(name == changed_kind);
        if decimal(current, name)? != expected {
            return Err(format!(
                "invalid {name} statistics transition: {previous:?} -> {current:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn parent_test() -> Result<(), Box<dyn Error>> {
    let mut monitor = Monitor::spawn()?;
    monitor.wait_ready()?;
    let (scenario_pid, scenario) = run_scenario()?;
    let duplicate = escaped_hex(scenario.get("duplicate").ok_or("missing duplicate path")?)?;
    let distinct = escaped_hex(scenario.get("distinct").ok_or("missing distinct path")?)?;
    let target_pid = scenario.get("target").ok_or("missing target pid")?;

    let deadline = Instant::now() + DEADLINE;
    let mut domain = None;
    let mut ruleset = None;
    let mut duplicate_counts = Vec::new();
    let mut distinct_seen = false;
    let mut signal_seen = false;
    let mut ruleset_dropped = false;
    let mut last_stats = None;
    let mut pending_stats_kind = None;
    let mut correlated_stats = 0;
    let mut domain_deallocation_seen = false;
    while !(duplicate_counts == [1, 2]
        && distinct_seen
        && signal_seen
        && ruleset_dropped
        && domain_deallocation_seen
        && correlated_stats == 4)
    {
        let (stream, line) = monitor.recv_before(deadline)?;
        let line = line?;
        if stream == Stream::Stderr {
            monitor.stderr.push(line);
            continue;
        }
        let record = parse_record(&line)?;
        if pending_stats_kind.is_some() && record.kind != "STATS" {
            return Err(format!("statistics did not immediately follow denial: {record:?}").into());
        }
        match record.kind.as_str() {
            "DOMAIN" => {
                if record.fields["creator"].ends_with(&format!("[{scenario_pid}]")) {
                    domain = Some(record.fields["domain"].clone());
                    ruleset = Some(record.fields["ruleset"].clone());
                    let (ruleset_id, version) = record.fields["ruleset"]
                        .split_once('.')
                        .ok_or("invalid scenario ruleset identity")?;
                    if record.fields["parent"] != "0"
                        || u64::from_str_radix(&record.fields["domain"], 16)? == 0
                        || u64::from_str_radix(ruleset_id, 16)? == 0
                        || version.parse::<u32>().is_err()
                    {
                        return Err(format!("incomplete scenario domain: {record:?}").into());
                    }
                }
            }
            "DROP_RULESET" if ruleset.as_ref() == Some(&record.fields["ruleset"]) => {
                ruleset_dropped = true;
            }
            "DENIAL" if domain.as_ref() == Some(&record.fields["domain"]) => {
                let count = decimal(&record, "count")?;
                let changed_kind =
                    if record.fields["type"] == "FS" && record.fields["target"] == duplicate {
                        duplicate_counts.push(count);
                        Some("fs")
                    } else if record.fields["type"] == "FS" && record.fields["target"] == distinct {
                        distinct_seen = count == 1;
                        Some("fs")
                    } else if record.fields["type"] == "SIGNAL"
                        && record.fields["target"].starts_with(&format!("pid:{target_pid}:"))
                    {
                        signal_seen = count == 1 && record.fields["target_domain"] == "0";
                        Some("signal")
                    } else {
                        None
                    };
                if let Some(kind) = changed_kind {
                    if pending_stats_kind.replace(kind).is_some() || last_stats.is_none() {
                        return Err(format!("missing preceding statistics: {record:?}").into());
                    }
                }
                if record.fields["same_exec"] != "1"
                    || !matches!(record.fields["logged"].as_str(), "0" | "1")
                    || record.fields["age"].is_empty()
                {
                    return Err(format!("invalid denial values: {record:?}").into());
                }
            }
            "STATS" => {
                assert_stats(&record)?;
                if let Some(previous) = last_stats.as_ref() {
                    domain_deallocation_seen |= is_domain_deallocation(previous, &record)?;
                }
                if let Some(kind) = pending_stats_kind.take() {
                    assert_stats_transition(
                        last_stats.as_ref().ok_or("missing previous statistics")?,
                        &record,
                        kind,
                    )?;
                    correlated_stats += 1;
                }
                last_stats = Some(record);
            }
            _ => {}
        }
    }

    if domain.is_none() {
        return Err("missing explicit scenario domain lifecycle".into());
    }
    let _diagnostics = monitor.finish()?;
    Ok(())
}

#[test]
#[ignore = "requires the fixed ABI 11 guest and BPF privileges"]
fn batch_integration() -> Result<(), Box<dyn Error>> {
    match env::var("LANDLOCK_CRATE_TEST_ABI") {
        Ok(value) if value == "11" => {}
        Ok(value) => panic!("LANDLOCK_CRATE_TEST_ABI must be 11, got {value:?}"),
        Err(error) => return Err(error.into()),
    }

    match env::var("LLTOP_TEST_MODE") {
        Ok(mode) if mode == "target" => target_helper(),
        Ok(mode) if mode == "scenario" => scenario_helper(),
        Ok(mode) => Err(format!("unknown LLTOP_TEST_MODE: {mode}").into()),
        Err(env::VarError::NotPresent) => parent_test(),
        Err(error) => Err(error.into()),
    }
}
