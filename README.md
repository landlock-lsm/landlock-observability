# Landlock observability

landlock-observability is a Linux-only Rust library for observing Landlock.
It embeds BPF programs that collect selected Landlock BTF tracepoints and
exposes typed, semantic events.  Applications can consume the
event stream directly, reconstruct partial ruleset and domain state,
and optionally aggregate repeated denials.

This is an observer, not an audit log or a complete snapshot.  Collection starts
only after the BPF programs attach, events can be lost in the kernel or in the
bounded userspace delivery queue, and events from different CPUs can arrive in
an order that does not reflect their timestamps.  Captured strings have fixed
bounds and report truncation.  Objects created or destroyed outside the
observed interval can therefore remain unknown or only partly known.  Consumers
must not interpret a missing event or an unknown state field as evidence that an
action or object did not exist.

> **Memory-use warning:** `state::State` currently has no capacity or eviction
> policy. It retains reconstructed rulesets, domains, and rules, plus one
> enforcement event per observed TID in each domain, until it is dropped.
> Memory can therefore grow without a configured bound in a long-running
> process. Configurable retention limits and eviction are planned but are not
> implemented yet; the bounded collector queue and `DenialAggregator` do not
> bound `State`.

## Build requirements

The minimum supported Rust version is **1.88**.  Normal builds require Linux,
Cargo and rustc, `clang` with the BPF target, a C build toolchain and `make`,
`pkg-config`, and the development files for libelf and zlib.  For example,
distributions commonly package the latter as `libelf-dev`/`zlib1g-dev` or
`elfutils-libelf-devel`/`zlib-devel`.  The Rust dependencies build their vendored
libbpf, so a system libbpf development package is not required.

A normal build uses the committed minimal CO-RE declarations and generated
access-name tables.  It needs **no kernel source tree, running-kernel headers,
Python, bpftool, tracefs mount, or privileged BPF loading**.  Those are not
build-time requirements; Python and bpftool are used only by maintainer checks.

```console
cargo build --locked
```

The project also provides
[lltop](https://github.com/landlock-lsm/landlock-observability/tree/main/lltop),
an interactive and batch monitor. After satisfying the runtime requirements
below, run `lltop` without arguments for its terminal interface, or run
`lltop --batch` for the stable line protocol. Batch mode reports
collector readiness as `LLTOP_READY` on flushed standard error, then writes
immediately flushed records to standard output when relevant reconstructed
state changes:

```text
DOMAIN domain=<hex> parent=<hex|?> ruleset=<hex>.<version>|? creator=<comm>[<tgid>]|? no_new_privs=<0|1|?>
DROP_RULESET ruleset=<hex>.<version>
DENIAL type=<kind> domain=<hex> blockers=<names|hex> target=<summary> count=<n> age=<elapsed> same_exec=<0|1> logged=<0|1> [<tracee_domain|target_domain|peer_domain>=<hex>]
STATS domains=<allocated>/<total> denials=<n> (fs=<n> net=<n> ptrace=<n> signal=<n> abstract_unix=<n>)
```

`DENIAL` types are `FS`, `NET`, `PTRACE`, `SIGNAL`, and `ABSTRACT_UNIX`.
IDs use lowercase hexadecimal without `0x`; `?` means unknown. Relational
`tracee_domain`, `target_domain`, and `peer_domain` identify the other party for
ptrace, signal, and abstract UNIX socket denials respectively; a value of `0`
means that party was unsandboxed. The domain-level `no_new_privs` field is
unknown before an enforcement observation and uses weakest-wins semantics over
the latest observation for each observed enforcing TID: `1` only when all such
observations have it set, and `0` when any lacks it. Observed TIDs are not a
live-thread census, so no ratio is reported. Missing `no_new_privs` means
privilege gain is possible; this does not identify a capability used to enforce
the domain or claim an escape from a Landlock domain. Kernel-captured bytes
outside ASCII letters,
digits, `_`, `-`, `.`, and `/` are unambiguously escaped as lowercase `\xNN`.
Unknown access bits remain numeric. Every `target` summary is one
whitespace-free token; separators captured within paths or command names remain
byte-escaped. The complete protocol—including target summaries, access-name
categories, counter semantics, age formatting, and readiness ordering—is
specified in the lltop README.

A normal `cargo test --locked` run does not load BPF.  The `kernel_events`
integration test is explicitly ignored in normal Cargo runs because it requires
the pinned landlock-test-tools x86_64 guest.  After building and locating the
exact test executable on the host, run it in that guest:

```console
./landlock-test-tools/x86-run.sh /path/to/bzImage -- \
  env LANDLOCK_CRATE_TEST_ABI=11 /path/to/kernel_events-test \
  --ignored --exact kernel_events --test-threads 1
```

A missing, empty, or different ABI value is an error.  The CI workflow builds
the fixed Linux revision with the test tools' default light x86_64
configuration, checks the generated BPF object's CO-RE declarations against
that kernel, and runs the test in a fresh guest.  The x86 harness runs the test
as the invoking UID while preserving capabilities.  It requires `virtme-ng`
and `qemu-system-x86`.

This privileged test is intentionally not attempted directly on the host.

## Runtime requirements

Creating a `Collector` loads BPF into the running kernel and attaches tracing
programs.  Dynamically linked builds require the target userspace to provide
libelf and zlib (normally `libelf.so.1` and `libz.so.1`).

The target kernel must provide Landlock tracing-interface generation 1, the
complete set of twelve BTF tracepoints and callback types introduced in Linux
v7.3-rc1 and listed below.  It also needs Landlock, the BPF syscall, BPF tracing
events, BPF ring buffers, and usable vmlinux BTF, conventionally exposed at
`/sys/kernel/btf/vmlinux`.  Relevant kernel options include
`CONFIG_SECURITY_LANDLOCK`, `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`,
`CONFIG_PERF_EVENTS`, `CONFIG_BPF_EVENTS`, `CONFIG_TRACING`, and
`CONFIG_DEBUG_INFO_BTF`.  The `tp_btf` attachment type lets the BPF verifier
validate each callback signature against this target BTF during load.

The collecting process must be allowed to load BPF programs and attach tracing
programs—typically by running as root or with `CAP_BPF` and `CAP_PERFMON`—and
may still be restricted by kernel lockdown, LSM policy, or BPF-related sysctls.
Collection does not require the BPF LSM, a bpffs, tracefs, or debugfs mount, a
kernel source or header tree, clang, bpftool, or Python on the target.

Tracepoint attachment is not exclusive.  Each collector loads its own twelve
program instances and ring-buffer map, and other collectors or tracing tools
may attach programs to the same tracepoints.  Every attached program runs for
each occurrence, with no cross-program ordering guarantee.  Multiple collectors
therefore receive independent event copies and multiply kernel execution,
memory, links, file descriptors, and independently bounded loss.

`Collector::new()` and `Collector::with_event_capacity()` report startup errors
synchronously.  A successful return means the embedded object was opened and
loaded, all programs were attached, and the ring-buffer consumer was created.
The error kind identifies whether validation, worker spawning, object opening,
loading, attachment, ring setup, or an early worker stop failed.

The collector has a bounded queue and its BPF ring-buffer callback never blocks
waiting for userspace.  `event_capacity` bounds event-bearing and
non-terminal-error delivery queue entries.  If this queue fills, entries are
omitted and a coalesced `OutputQueueFull` notification is paired as control
metadata with, and reported before, the next accepted delivery; it does not
consume a separate channel slot.  That error describes **only userspace
output-queue loss**; it does not account
for failed kernel ring-buffer reservations, activity before attachment, or any
other kernel-side loss.

## Data model

* `event::Event` is the primary raw semantic observation and can be processed or
  retained without either higher-level helper.  Unknown producer event kinds
  remain `Event::Unknown` with their numeric kind and captured fixed record
  length.  Access
  masks preserve all bits and expose known names and unknown bits separately.
* `state::State` applies events to reconstruct partial ruleset and domain facts.
  It explicitly retains unknown values and monotonic lifecycle facts; it is not
  a complete kernel snapshot and does not retain individual denials. It has no
  capacity or eviction policy and retains reconstructed rulesets, domains,
  rules, and one enforcement event per observed TID per domain until dropped,
  so memory can grow without a configured bound. Enforcement events retain
  their `no_new_privs` values and expose the domain's weakest selected value
  without treating observed TIDs as a live-thread census.
* `aggregate::DenialAggregator` is optional.  It has an exact configurable
  capacity (1000 by default), groups denials by their semantic domain/blocker/
  target key, refreshes recency on every matching observation, and evicts the
  least recently observed key when a new key is inserted at capacity.  Its
  saturating occurrence count is local to that aggregator and is independent of
  the kernel's cumulative denial count.

This offline example compiles and does not load BPF:

```rust
use landlock_observability::aggregate::DenialAggregator;
use landlock_observability::event::{Event, KernelTimestamp, UnknownEvent};
use landlock_observability::state::State;

fn process(event: &Event, state: &mut State, denials: &mut DenialAggregator) {
    state.apply(event);
    denials.observe(event);
}

let event = Event::Unknown(UnknownEvent::new(
    KernelTimestamp::from_nanoseconds(1),
    255,
    32,
));
let mut state = State::new();
let mut denials = DenialAggregator::new();
process(&event, &mut state, &mut denials);
assert!(state.domains().next().is_none());
assert!(denials.is_empty());
```

Live collection is privileged as described under **Runtime requirements**; the
following example does not imply that an unprivileged process can start it:

```no_run
use landlock_observability::collector::Collector;
use std::error::Error;
use std::time::Duration;

fn main() -> Result<(), Box<dyn Error>> {
    let mut collector = Collector::new()?;
    let event = collector.recv_timeout(Duration::from_secs(1))?;
    println!("{event:?}");
    Ok(())
}
```

## Tracepoint coverage

Landlock tracing-interface generation 1 consists of these twelve BTF
tracepoint families and the fields represented by the corresponding typed
events.  The collector treats them as one compatibility unit: startup succeeds
only after all of them are loaded and attached:

1. `landlock_create_ruleset`
2. `landlock_add_rule_fs`
3. `landlock_add_rule_net`
4. `landlock_create_domain`
5. `landlock_enforce_domain`
6. `landlock_deny_access_fs`
7. `landlock_deny_access_net`
8. `landlock_deny_ptrace`
9. `landlock_deny_scope_signal`
10. `landlock_deny_scope_abstract_unix_socket`
11. `landlock_free_domain`
12. `landlock_free_ruleset`

The high-volume `landlock_check_rule` family is intentionally not collected.

## Licensing and distribution

The root package has the SPDX expression
`(MIT OR Apache-2.0) AND GPL-2.0-only`.  Rust and other original userspace
source is available under MIT or Apache-2.0.  The separately executing embedded
BPF program and minimal Linux kernel declarations are GPL-2.0-only.

The kernel's BPF licensing model permits a userspace application and a BPF
program to carry different licenses because they are separate programs; see
<https://docs.kernel.org/bpf/bpf_licensing.html>.  Distributors must preserve
the applicable copyright and license notices and provide the corresponding BPF
source with distributed binaries as required.  See `COPYRIGHT`, `LICENSE-MIT`,
`LICENSE-APACHE`, `LICENSE-GPL`, and the per-file SPDX identifiers for the exact
notices and boundaries.
