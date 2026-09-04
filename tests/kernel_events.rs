// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashSet;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::linux::fs::MetadataExt;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use landlock::{
    Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, RestrictSelfAttr, Ruleset,
    RulesetAttr, RulesetCreatedAttr, Scope, ABI,
};
use landlock_observability::collector::Collector;
use landlock_observability::event::{
    DenialContext, DomainId, DomainMembership, EnforceDomainEvent, Event, FilesystemAccess,
    NetworkAccess, RulesetId, ScopeAccess,
};
use landlock_observability::state::{DomainParent, LifecycleState, RulesetVersion, State};
use nix::errno::Errno;
use nix::sys::{ptrace, signal};
use nix::unistd::Pid;
use wait_timeout::ChildExt;

const DEADLINE: Duration = Duration::from_secs(10);
const TASK_COMM_MAX: usize = 15;
const ALLOWED_PORT: u16 = 9;
const DENIED_PORT: u16 = 1;
// ABI v9 is the newest ABI supported by the `landlock` 0.4.7 crate.
const TESTED_ACCESS_ABI: ABI = ABI::V9;

struct ProcessGuard(Child);

impl std::ops::Deref for ProcessGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ProcessGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ExpectedEventKind {
    CreateRuleset,
    AddRuleFs,
    AddRuleNet,
    CreateDomain,
    EnforceDomain,
    DenyAccessFs,
    DenyAccessFsDifferentExec,
    DenyAccessNet,
    DenyPtrace,
    DenyScopeSignal,
    DenyScopeAbstractUnixSocket,
    FreeDomain,
    FreeRuleset,
}

const EXPECTED_EVENT_KINDS: &[ExpectedEventKind] = &[
    ExpectedEventKind::CreateRuleset,
    ExpectedEventKind::AddRuleFs,
    ExpectedEventKind::AddRuleNet,
    ExpectedEventKind::CreateDomain,
    ExpectedEventKind::EnforceDomain,
    ExpectedEventKind::DenyAccessFs,
    ExpectedEventKind::DenyAccessFsDifferentExec,
    ExpectedEventKind::DenyAccessNet,
    ExpectedEventKind::DenyPtrace,
    ExpectedEventKind::DenyScopeSignal,
    ExpectedEventKind::DenyScopeAbstractUnixSocket,
    ExpectedEventKind::FreeDomain,
    ExpectedEventKind::FreeRuleset,
];

macro_rules! expect_event {
    ($event:expr, $kind:expr, $variant:ident) => {{
        let Event::$variant(value) = $event else {
            return Err(format!("mismatched scenario event kind {:?}: {:?}", $kind, $event).into());
        };
        value
    }};
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn into_inner(mut self) -> Child {
        self.0.take().expect("a child guard owns its process")
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("a child guard owns its process")
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("a child guard owns its process")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Target {
    child: Child,
    input: Option<ChildStdin>,
    _output: BufReader<ChildStdout>,
    comm: Vec<u8>,
}

impl Target {
    fn spawn(mode: &str, abstract_name: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let executable = env::current_exe()?;
        let mut command = Command::new(executable);
        command
            .arg("--ignored")
            .arg("--exact")
            .arg("kernel_events")
            .arg("--nocapture")
            .env("KERNEL_EVENTS_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if let Some(name) = abstract_name {
            command.env("KERNEL_EVENTS_ABSTRACT_NAME", name);
        }
        let mut child = ChildGuard::new(command.spawn()?);
        let output = child.stdout.take().ok_or("target stdout was not piped")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            let mut output = BufReader::new(output);
            let result = loop {
                let mut line = String::new();
                match output.read_line(&mut line) {
                    Ok(0) => {
                        break Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "missing READY line",
                        ));
                    }
                    Ok(_) if line.contains("READY") => break Ok(()),
                    Ok(_) => {}
                    Err(error) => break Err(error),
                }
            };
            let _ = sender.send((result, output));
        });
        let (ready, output) = receiver.recv_timeout(DEADLINE)?;
        ready?;
        reader
            .join()
            .map_err(|_| "target readiness reader panicked")?;
        let input = child.stdin.take().ok_or("target stdin was not piped")?;
        let comm = process_comm(child.id())?;
        Ok(Self {
            child: child.into_inner(),
            input: Some(input),
            _output: output,
            comm,
        })
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn finish(mut self) -> Result<(), Box<dyn Error>> {
        drop(self.input.take());
        let status = wait_for_exit(&mut self.child, DEADLINE)?;
        if !status.success() {
            return Err(format!("target {} exited with {status}", self.child.id()).into());
        }
        Ok(())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        drop(self.input.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, Box<dyn Error>> {
    if let Some(status) = child.wait_timeout(timeout)? {
        return Ok(status);
    }
    let _ = child.kill();
    let status = child.wait()?;
    Err(format!(
        "child {} missed its deadline and exited with {status}",
        child.id()
    )
    .into())
}

fn process_comm(pid: u32) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut comm = fs::read(format!("/proc/{pid}/comm"))?;
    if comm.last() == Some(&b'\n') {
        comm.pop();
    }
    comm.truncate(TASK_COMM_MAX);
    if comm.is_empty() {
        return Err(format!("process {pid} has an empty comm").into());
    }
    Ok(comm)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() & 1 != 0 {
        return Err(format!("odd-length hexadecimal value: {value}").into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}

fn target_helper(abstract_server: bool) -> Result<(), Box<dyn Error>> {
    let _listener = if abstract_server {
        let name = env::var("KERNEL_EVENTS_ABSTRACT_NAME")?;
        let address = SocketAddr::from_abstract_name(name.as_bytes())?;
        Some(UnixListener::bind_addr(&address)?)
    } else {
        None
    };
    println!("READY");
    io::stdout().flush()?;
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    Ok(())
}

fn assert_errno(error: &io::Error, expected: Errno) {
    assert_eq!(error.raw_os_error(), Some(expected as i32));
}

fn post_exec_helper() -> Result<(), Box<dyn Error>> {
    let error = fs::read_dir("/proc").unwrap_err();
    assert_errno(&error, Errno::EACCES);
    Ok(())
}

fn scenario_helper() -> Result<(), Box<dyn Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let abstract_name = format!("llobs-{}-{unique}", std::process::id());
    let ptrace_target = Target::spawn("target", None)?;
    let signal_target = Target::spawn("target", None)?;
    let unix_target = Target::spawn("abstract-target", Some(&abstract_name))?;

    let allowed_path = env::current_dir()?.canonicalize()?;
    let allowed_metadata = fs::metadata(&allowed_path)?;
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::ReadDir)?
        .handle_access(AccessNet::ConnectTcp)?
        .scope(Scope::from_all(TESTED_ACCESS_ABI))?
        .create()?
        .add_rule(PathBeneath::new(
            PathFd::new(&allowed_path)?,
            AccessFs::ReadDir,
        ))?
        .add_rule(NetPort::new(ALLOWED_PORT, AccessNet::ConnectTcp))?;
    let status = ruleset.restrict_self()?;
    if status.ruleset != landlock::RulesetStatus::FullyEnforced {
        return Err(format!("ruleset was not fully enforced: {status:?}").into());
    }

    let fs_error = fs::read_dir("/proc").unwrap_err();
    assert_errno(&fs_error, Errno::EACCES);
    let network_error =
        TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DENIED_PORT)).unwrap_err();
    assert_errno(&network_error, Errno::EACCES);
    assert_eq!(
        ptrace::attach(Pid::from_raw(ptrace_target.id() as i32)),
        Err(Errno::EPERM)
    );
    assert_eq!(
        signal::kill(
            Pid::from_raw(signal_target.id() as i32),
            signal::Signal::SIGUSR1,
        ),
        Err(Errno::EPERM)
    );
    let unix_address = SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
    let unix_error = UnixStream::connect_addr(&unix_address).unwrap_err();
    assert_errno(&unix_error, Errno::EPERM);

    let post_exec = Command::new(env::current_exe()?)
        .arg("--ignored")
        .arg("--exact")
        .arg("kernel_events")
        .arg("--nocapture")
        .env("KERNEL_EVENTS_MODE", "post-exec")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()?;
    if !post_exec.success() {
        return Err(format!("post-exec helper exited with {post_exec}").into());
    }

    let enforcing_tid = u32::try_from(nix::unistd::gettid().as_raw())?;
    let creator_comm = process_comm(enforcing_tid)?;
    println!(
        "DONE {} {} {} {} {} {} {} {} {} {} {}",
        allowed_metadata.st_dev(),
        allowed_metadata.st_ino(),
        enforcing_tid,
        ptrace_target.id(),
        signal_target.id(),
        unix_target.id(),
        encode_hex(&creator_comm),
        encode_hex(&ptrace_target.comm),
        encode_hex(&signal_target.comm),
        encode_hex(allowed_path.as_os_str().as_bytes()),
        abstract_name,
    );
    io::stdout().flush()?;

    ptrace_target.finish()?;
    signal_target.finish()?;
    unix_target.finish()?;
    Ok(())
}

fn no_new_privs_tsync_helper(no_new_privs: bool) -> Result<(), Box<dyn Error>> {
    // This sibling predates any PR_SET_NO_NEW_PRIVS call. Creating it later
    // would test clone inheritance instead of TSYNC synchronization.
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let sibling = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_rx.recv().unwrap();
    });
    ready_rx.recv_timeout(DEADLINE)?;

    let status = Ruleset::default()
        .handle_access(AccessFs::ReadFile)?
        .create()?
        .all_threads(true)?
        .no_new_privs(no_new_privs)
        .restrict_self();
    done_tx.send(())?;
    sibling.join().map_err(|_| "TSYNC sibling panicked")?;
    let status = status?;
    if status.ruleset != landlock::RulesetStatus::FullyEnforced || !status.all_threads {
        return Err(format!("ruleset was not fully synchronized: {status:?}").into());
    }
    Ok(())
}

fn has_cap_sys_admin() -> Result<bool, Box<dyn Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .ok_or("missing CapEff in /proc/self/status")?;
    Ok(u64::from_str_radix(value, 16)? & (1 << 21) != 0)
}

fn no_new_privs_tsync_test(no_new_privs: bool) -> Result<(), Box<dyn Error>> {
    let mut collector = Collector::with_event_capacity(128)?;
    let executable = env::current_exe()?;
    let mode = if no_new_privs {
        "nnp-tsync-1"
    } else {
        "nnp-tsync-0"
    };
    let mut child = ProcessGuard(
        Command::new(executable)
            .arg("--ignored")
            .arg("--exact")
            .arg("kernel_events")
            .arg("--nocapture")
            .env("KERNEL_EVENTS_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()?,
    );
    let creator_tgid = child.id();
    let deadline = Instant::now() + DEADLINE;
    let mut domain_id = None;
    let mut candidates = Vec::new();
    loop {
        if domain_id.is_some()
            && candidates
                .iter()
                .filter(|event: &&EnforceDomainEvent| Some(event.domain_id()) == domain_id)
                .count()
                >= 2
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "timed out waiting for two TSYNC no_new_privs={no_new_privs} observations: {candidates:?}"
            )
            .into());
        }
        match collector.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::CreateDomain(event)) if event.creator_tgid() == creator_tgid => {
                domain_id = Some(event.domain_id());
            }
            Ok(Event::EnforceDomain(event)) => candidates.push(event),
            Ok(Event::Unknown(event)) => {
                return Err(format!("unknown event during TSYNC scenario: {event:?}").into());
            }
            Ok(_) | Err(landlock_observability::collector::ReceiveTimeoutError::Timeout) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let status = wait_for_exit(&mut child, DEADLINE)?;
    if !status.success() {
        return Err(format!("TSYNC no_new_privs={no_new_privs} child exited with {status}").into());
    }
    loop {
        match collector.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::EnforceDomain(event)) => candidates.push(event),
            Ok(Event::Unknown(event)) => {
                return Err(format!("unknown event during TSYNC drain: {event:?}").into());
            }
            Ok(_) => {}
            Err(landlock_observability::collector::ReceiveTimeoutError::Timeout) => break,
            Err(error) => return Err(error.into()),
        }
    }
    let observations = candidates
        .into_iter()
        .filter(|event| Some(event.domain_id()) == domain_id)
        .collect::<Vec<_>>();
    let tids = observations
        .iter()
        .map(|event| event.enforcing_tid())
        .collect::<HashSet<_>>();
    // The Rust test harness may already have a sibling in addition to the one
    // created explicitly above. Every eligible thread must emit exactly once.
    assert!(observations.len() >= 2);
    assert_eq!(tids.len(), observations.len());
    assert_eq!(
        observations.iter().filter(|event| event.complete()).count(),
        1
    );
    assert!(observations.iter().all(|event| event.process_wide()));
    assert!(observations
        .iter()
        .all(|event| event.no_new_privs() == no_new_privs));
    Ok(())
}

fn filesystem_access(access: AccessFs) -> FilesystemAccess {
    FilesystemAccess::from_bits(
        u32::try_from(access as u64).expect("filesystem access bit fits u32"),
    )
}

fn network_access(access: AccessNet) -> NetworkAccess {
    NetworkAccess::from_bits(u32::try_from(access as u64).expect("network access bit fits u32"))
}

// These fixed-kernel expectations contain only known bits.  Access values
// preserve unknown bits, so exact equality also detects unexpected new bits.
fn normalized_filesystem_rule_access() -> FilesystemAccess {
    let all_known = FilesystemAccess::all_known_names().fold(0, |bits, access| bits | access.bit());
    // Historically, Refer stays denied instead of normalizing like unhandled rights.
    FilesystemAccess::from_bits(all_known & !filesystem_access(AccessFs::Refer).bits())
}

fn all_known_network_access() -> NetworkAccess {
    NetworkAccess::from_bits(
        NetworkAccess::all_known_names().fold(0, |bits, access| bits | access.bit()),
    )
}

fn all_known_scope_access() -> ScopeAccess {
    ScopeAccess::from_bits(
        ScopeAccess::all_known_names().fold(0, |bits, access| bits | access.bit()),
    )
}

fn correlated_event_kind(
    event: &Event,
    ruleset_id: RulesetId,
    domain_id: DomainId,
) -> Result<Option<ExpectedEventKind>, Box<dyn Error>> {
    let kind = match event {
        Event::CreateRuleset(value) => {
            (value.ruleset_id() == ruleset_id).then_some(ExpectedEventKind::CreateRuleset)
        }
        Event::AddRuleFs(value) => {
            (value.ruleset_id() == ruleset_id).then_some(ExpectedEventKind::AddRuleFs)
        }
        Event::AddRuleNet(value) => {
            (value.ruleset_id() == ruleset_id).then_some(ExpectedEventKind::AddRuleNet)
        }
        Event::CreateDomain(value) => {
            (value.domain_id() == domain_id).then_some(ExpectedEventKind::CreateDomain)
        }
        Event::EnforceDomain(value) => {
            (value.domain_id() == domain_id).then_some(ExpectedEventKind::EnforceDomain)
        }
        Event::DenyAccessFs(value) => (value.context().hierarchy().domain_id() == domain_id)
            .then_some(if value.context().same_exec() {
                ExpectedEventKind::DenyAccessFs
            } else {
                ExpectedEventKind::DenyAccessFsDifferentExec
            }),
        Event::DenyAccessNet(value) => (value.context().hierarchy().domain_id() == domain_id)
            .then_some(ExpectedEventKind::DenyAccessNet),
        Event::DenyPtrace(value) => (value.context().hierarchy().domain_id() == domain_id)
            .then_some(ExpectedEventKind::DenyPtrace),
        Event::DenyScopeSignal(value) => (value.context().hierarchy().domain_id() == domain_id)
            .then_some(ExpectedEventKind::DenyScopeSignal),
        Event::DenyScopeAbstractUnixSocket(value) => (value.context().hierarchy().domain_id()
            == domain_id)
            .then_some(ExpectedEventKind::DenyScopeAbstractUnixSocket),
        Event::FreeDomain(value) => {
            (value.domain_id() == domain_id).then_some(ExpectedEventKind::FreeDomain)
        }
        Event::FreeRuleset(value) => {
            (value.ruleset_id() == ruleset_id).then_some(ExpectedEventKind::FreeRuleset)
        }
        Event::Unknown(value) => return Err(format!("unknown event: {value:?}").into()),
        _ => return Err(format!("unhandled event variant: {event:?}").into()),
    };
    Ok(kind)
}

fn record_correlated_event(
    seen: &mut HashSet<ExpectedEventKind>,
    kind: ExpectedEventKind,
    event: &Event,
) -> Result<(), Box<dyn Error>> {
    if !seen.insert(kind) {
        return Err(format!("duplicate scenario event kind {kind:?}: {event:?}").into());
    }
    Ok(())
}

fn assert_context(
    context: &DenialContext,
    domain_id: DomainId,
    creator_tgid: u32,
    creator_comm: &[u8],
    same_exec: bool,
) {
    assert_eq!(context.hierarchy().domain_id(), domain_id);
    assert_eq!(context.hierarchy().parent_id(), None);
    assert_eq!(context.hierarchy().creator_tgid(), creator_tgid);
    assert_eq!(context.hierarchy().creator_comm().as_bytes(), creator_comm);
    assert_eq!(context.same_exec(), same_exec);
    assert_ne!(context.cumulative_denial_count(), 0);
}

fn parent_test() -> Result<(), Box<dyn Error>> {
    let mut collector = Collector::with_event_capacity(4096)?;
    let executable = env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("--ignored")
        .arg("--exact")
        .arg("kernel_events")
        .arg("--nocapture")
        .env("KERNEL_EVENTS_MODE", "scenario")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let creator_tgid = child.id();
    let output = child.stdout.take().ok_or("scenario stdout was not piped")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut output = BufReader::new(output);
        let result = loop {
            let mut line = String::new();
            match output.read_line(&mut line) {
                Ok(0) => {
                    break Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "missing DONE line",
                    ));
                }
                Ok(_) => {
                    if let Some(offset) = line.find("DONE ") {
                        break Ok(line[offset..].trim_end().to_owned());
                    }
                }
                Err(error) => break Err(error),
            }
        };
        let _ = sender.send((result, output));
    });
    let (done, _output) = match receiver.recv_timeout(DEADLINE) {
        Ok((Ok(done), output)) => (done, output),
        Ok((Err(error), _)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
    };
    let status = wait_for_exit(&mut child, DEADLINE)?;
    reader
        .join()
        .map_err(|_| "scenario output reader panicked")?;
    if !status.success() {
        return Err(format!("scenario exited with {status}").into());
    }

    let fields: Vec<&str> = done.split_whitespace().collect();
    if fields.len() != 12 {
        return Err(format!("invalid scenario result: {done}").into());
    }
    let allowed_device: u64 = fields[1].parse()?;
    let allowed_inode: u64 = fields[2].parse()?;
    let enforcing_tid: u32 = fields[3].parse()?;
    let ptrace_tgid: u32 = fields[4].parse()?;
    let signal_tgid: u32 = fields[5].parse()?;
    let unix_pid: u32 = fields[6].parse()?;
    let creator_comm = decode_hex(fields[7])?;
    let ptrace_comm = decode_hex(fields[8])?;
    let signal_comm = decode_hex(fields[9])?;
    let allowed_path = decode_hex(fields[10])?;
    assert_ne!(enforcing_tid, creator_tgid);

    let mut events = Vec::new();
    let mut scenario_ids = None;
    let mut seen = HashSet::new();
    let deadline = Instant::now() + DEADLINE;
    let (ruleset_id, domain_id) = loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!("missing correlated events before deadline: {events:#?}").into());
        }
        let event = collector.recv_timeout(deadline - now)?;
        if let Event::Unknown(value) = &event {
            return Err(format!("unknown event: {value:?}").into());
        }

        let new_scenario_ids = match &event {
            Event::CreateDomain(value) if value.creator_tgid() == creator_tgid => {
                Some((value.ruleset_id(), value.domain_id()))
            }
            _ => None,
        };
        events.push(event);

        if let Some(ids) = new_scenario_ids {
            if scenario_ids.replace(ids).is_some() {
                return Err("duplicate scenario domain creation".into());
            }
            for event in &events {
                if let Some(kind) = correlated_event_kind(event, ids.0, ids.1)? {
                    record_correlated_event(&mut seen, kind, event)?;
                }
            }
        } else if let Some(ids) = scenario_ids {
            let event = events.last().expect("event was just pushed");
            if let Some(kind) = correlated_event_kind(event, ids.0, ids.1)? {
                record_correlated_event(&mut seen, kind, event)?;
            }
        }

        if let Some(ids) = scenario_ids {
            if seen.len() == EXPECTED_EVENT_KINDS.len()
                && EXPECTED_EVENT_KINDS.iter().all(|kind| seen.contains(kind))
            {
                break ids;
            }
        }
    };

    let mut denial_counts = Vec::new();
    let mut state = State::new();
    for event in &events {
        let Some(kind) = correlated_event_kind(event, ruleset_id, domain_id)? else {
            continue;
        };
        state.apply(event);
        match kind {
            ExpectedEventKind::CreateRuleset => {
                let value = expect_event!(event, kind, CreateRuleset);
                assert_ne!(value.ruleset_id().get(), 0);
                assert_eq!(value.ruleset_version(), 0);
                assert_eq!(value.handled_fs(), filesystem_access(AccessFs::ReadDir));
                assert_eq!(value.handled_net(), network_access(AccessNet::ConnectTcp));
                assert_eq!(value.scoped(), all_known_scope_access());
            }
            ExpectedEventKind::AddRuleFs => {
                let value = expect_event!(event, kind, AddRuleFs);
                assert_eq!(value.ruleset_id(), ruleset_id);
                assert_eq!(value.ruleset_version(), 1);
                // The fixed kernel normalizes rules with every known bit and
                // preserves unknown bits; this exact equality rejects either drift.
                assert_eq!(value.access_rights(), normalized_filesystem_rule_access());
                assert_eq!(value.device() as u64, allowed_device);
                assert_eq!(value.inode(), allowed_inode);
                assert_eq!(value.pathname().as_bytes(), allowed_path);
            }
            ExpectedEventKind::AddRuleNet => {
                let value = expect_event!(event, kind, AddRuleNet);
                assert_eq!(value.ruleset_id(), ruleset_id);
                assert_eq!(value.ruleset_version(), 2);
                // Derive this from the event API because the `landlock` 0.4.7
                // crate does not expose the fixed kernel's UDP rights through
                // AccessNet.
                assert_eq!(value.access_rights(), all_known_network_access());
                assert_eq!(value.port(), u64::from(ALLOWED_PORT));
            }
            ExpectedEventKind::CreateDomain => {
                let value = expect_event!(event, kind, CreateDomain);
                assert_eq!(value.ruleset_id(), ruleset_id);
                assert_eq!(value.ruleset_version(), 2);
                assert_eq!(value.parent_id(), None);
                assert_eq!(value.creator_tgid(), creator_tgid);
                assert_eq!(value.creator_comm().as_bytes(), creator_comm);
            }
            ExpectedEventKind::EnforceDomain => {
                let value = expect_event!(event, kind, EnforceDomain);
                assert_eq!(value.enforcing_tid(), enforcing_tid);
                assert!(value.complete());
                assert!(!value.process_wide());
                assert!(value.no_new_privs());
            }
            ExpectedEventKind::DenyAccessFs | ExpectedEventKind::DenyAccessFsDifferentExec => {
                let value = expect_event!(event, kind, DenyAccessFs);
                let after_exec = kind == ExpectedEventKind::DenyAccessFsDifferentExec;
                assert_context(
                    value.context(),
                    domain_id,
                    creator_tgid,
                    &creator_comm,
                    !after_exec,
                );
                if after_exec {
                    assert!(!value.context().logged());
                }
                denial_counts.push(value.context().cumulative_denial_count());
                assert_eq!(value.blockers(), filesystem_access(AccessFs::ReadDir));
                assert_ne!(value.device(), 0);
                assert_ne!(value.inode(), 0);
                assert_eq!(value.pathname().as_bytes(), b"/proc");
            }
            ExpectedEventKind::DenyAccessNet => {
                let value = expect_event!(event, kind, DenyAccessNet);
                assert_context(
                    value.context(),
                    domain_id,
                    creator_tgid,
                    &creator_comm,
                    true,
                );
                denial_counts.push(value.context().cumulative_denial_count());
                assert_eq!(value.blockers(), network_access(AccessNet::ConnectTcp));
                assert_eq!(value.source_port(), 0);
                assert_eq!(value.destination_port(), u64::from(DENIED_PORT));
            }
            ExpectedEventKind::DenyPtrace => {
                let value = expect_event!(event, kind, DenyPtrace);
                assert_context(
                    value.context(),
                    domain_id,
                    creator_tgid,
                    &creator_comm,
                    true,
                );
                denial_counts.push(value.context().cumulative_denial_count());
                assert_eq!(value.tracee_domain(), DomainMembership::Unsandboxed);
                assert_eq!(value.tracee_pid(), ptrace_tgid);
                assert_eq!(value.tracee_comm().as_bytes(), ptrace_comm);
            }
            ExpectedEventKind::DenyScopeSignal => {
                let value = expect_event!(event, kind, DenyScopeSignal);
                assert_context(
                    value.context(),
                    domain_id,
                    creator_tgid,
                    &creator_comm,
                    true,
                );
                denial_counts.push(value.context().cumulative_denial_count());
                assert_eq!(value.target_domain(), DomainMembership::Unsandboxed);
                assert_eq!(value.target_pid(), signal_tgid);
                assert_eq!(value.target_comm().as_bytes(), signal_comm);
            }
            ExpectedEventKind::DenyScopeAbstractUnixSocket => {
                let value = expect_event!(event, kind, DenyScopeAbstractUnixSocket);
                assert_context(
                    value.context(),
                    domain_id,
                    creator_tgid,
                    &creator_comm,
                    true,
                );
                denial_counts.push(value.context().cumulative_denial_count());
                assert_eq!(value.peer_domain(), DomainMembership::Unsandboxed);
                assert_eq!(value.peer_pid(), unix_pid);
            }
            ExpectedEventKind::FreeDomain => {
                let value = expect_event!(event, kind, FreeDomain);
                assert_eq!(value.domain_id(), domain_id);
                assert_eq!(value.denial_count(), 6);
            }
            ExpectedEventKind::FreeRuleset => {
                let value = expect_event!(event, kind, FreeRuleset);
                assert_eq!(value.ruleset_id(), ruleset_id);
                assert_eq!(value.ruleset_version(), 2);
            }
        }
    }
    denial_counts.sort_unstable();
    assert_eq!(denial_counts, [1, 2, 3, 4, 5, 6]);

    let ruleset = state
        .ruleset(ruleset_id)
        .ok_or("missing reconstructed ruleset")?;
    assert_eq!(state.ruleset_count(), 1);
    assert_eq!(ruleset.lifecycle(), LifecycleState::Deallocated);
    assert_eq!(ruleset.max_observed_version(), Some(2));
    assert_eq!(ruleset.final_version(), Some(2));
    assert_eq!(ruleset.filesystem_rule_count(), 1);
    assert_eq!(ruleset.network_rule_count(), 1);
    assert!(ruleset
        .filesystem_rule(allowed_device as u32, allowed_inode)
        .is_some());
    assert!(ruleset.network_rule(u64::from(ALLOWED_PORT)).is_some());

    let domain = state
        .domain(domain_id)
        .ok_or("missing reconstructed domain")?;
    assert_eq!(state.domain_count(), 1);
    assert_eq!(domain.lifecycle(), LifecycleState::Deallocated);
    assert_eq!(domain.parent(), Some(DomainParent::Root));
    assert_eq!(domain.creator_tgid(), Some(creator_tgid));
    assert_eq!(domain.ruleset(), Some(RulesetVersion::new(ruleset_id, 2)));
    assert_eq!(domain.no_new_privs(), Some(true));
    assert_eq!(domain.cumulative_denial_count(), Some(6));
    assert_eq!(domain.final_denial_count(), Some(6));
    assert_eq!(domain.enforcement_event_count(), 1);
    let enforcement = domain
        .enforcement_event(enforcing_tid)
        .ok_or("missing retained enforcement event")?;
    assert_eq!(enforcement.domain_id(), domain_id);
    assert_eq!(enforcement.enforcing_tid(), enforcing_tid);
    assert!(enforcement.complete());
    assert!(!enforcement.process_wide());
    assert!(!domain.any_process_wide_enforcement());
    Ok(())
}

#[test]
#[ignore = "requires the fixed ABI 11 guest"]
fn kernel_events() -> Result<(), Box<dyn Error>> {
    match env::var("LANDLOCK_CRATE_TEST_ABI") {
        Ok(value) if value == "11" => {}
        Ok(value) => panic!("LANDLOCK_CRATE_TEST_ABI must be 11, got {value:?}"),
        Err(error) => return Err(error.into()),
    }

    match env::var("KERNEL_EVENTS_MODE") {
        Ok(mode) if mode == "target" => target_helper(false),
        Ok(mode) if mode == "abstract-target" => target_helper(true),
        Ok(mode) if mode == "scenario" => scenario_helper(),
        Ok(mode) if mode == "post-exec" => post_exec_helper(),
        Ok(mode) if mode == "nnp-tsync-1" => no_new_privs_tsync_helper(true),
        Ok(mode) if mode == "nnp-tsync-0" => no_new_privs_tsync_helper(false),
        Ok(mode) => Err(format!("unknown KERNEL_EVENTS_MODE: {mode}").into()),
        Err(env::VarError::NotPresent) => {
            parent_test()?;
            no_new_privs_tsync_test(true)?;
            if !has_cap_sys_admin()? {
                return Err(
                    "no_new_privs=0 TSYNC coverage requires effective CAP_SYS_ADMIN in the fixed guest"
                        .into(),
                );
            }
            no_new_privs_tsync_test(false)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}
