# lltop

lltop is an interactive and batch monitor for Landlock. It uses the
landlock-observability library to attach the BPF collector,
reconstruct partial domain and ruleset state, and aggregate repeated denials.
The minimum supported Rust version is 1.88.

> **Memory-use warning:** Interactive and batch modes retain reconstructed
> `State`, which currently has no capacity or eviction policy. Memory can grow
> without a configured bound in a long-running process. Configurable retention
> limits and eviction are planned but are not implemented yet; the bounded
> collector queue and denial aggregator do not bound `State`.

The collector has the runtime requirements documented in the root README. In
particular, starting it normally requires root or suitable BPF and tracing
capabilities. The dependency embeds a separately executing GPL-2.0-only BPF
program; lltop itself is available under MIT or Apache-2.0.

## Interactive mode

Run `sudo lltop` without arguments to open the terminal interface. Its Domains,
Denials, Rulesets, and Stats tabs preserve selection by semantic object identity
while live observations reorder rows. Selecting a row opens a 40/60 list and
detail split; Enter on a domain follows its known frozen ruleset. Partial
late-start objects and deallocated tombstones remain visible.

Use `1`–`4` or Tab to change tabs, Up/Down to select, `p` to pause collector
polling, Enter to follow, and `q` to quit. Esc first closes details and then
quits. Mouse clicks select tabs and rows, the wheel moves three rows, and the
scrollbar can be dragged. Manual scrolling may move the selection off-screen;
Up/Down selection resumes following it. Mouse setup has no terminal
acknowledgement; its local write and flush result is ignored so keyboard
operation does not depend on mouse setup.

Denials are grouped by domain, blocked access, and semantic target. Groups and
targets prioritize impact and recency. `audit-visible` and `trace-only` report
the kernel's `logged` decision directly. Recency styling is based on the newest
kernel timestamp seen, with bands below 1, 5, and 30 seconds. All captured
strings are escaped before display, and long values wrap at comma-space, slash,
or space boundaries with indented continuations.

Raw mode, alternate-screen state, and attempted mouse reporting are owned by an
unwind-safe guard and restored on normal exit, errors, and panic. Mouse rollback
is conservatively armed before the enablement sequence is written.

## Batch mode

Batch mode remains explicit:

```console
sudo lltop --batch
```

After the collector has loaded and all programs have attached, lltop writes and
flushes an exact `LLTOP_READY` line on standard error. Consumers should ignore
startup diagnostics and begin the operation they want to observe only after
reading that line.

Standard output is a flushed, line-oriented stream. Changes produced by each
event are emitted immediately and followed by one `STATS` line. Unchanged
lifecycle observations do not repeat an identity; a domain is emitted again when
newly learned facts change its record. Repeated denials emit only a changed
aggregate count. Events that do not affect this protocol are silent.
Nonterminal malformed-sample and full-output-queue collector errors are warned
about on standard error and collection continues; terminal polling or
worker-stop errors end the process.
The records are:

```text
DOMAIN domain=<hex> parent=<hex|?> ruleset=<hex>.<version>|? creator=<comm>[<tgid>]|?
DROP_RULESET ruleset=<hex>.<version>
DENIAL type=<kind> domain=<hex> blockers=<names|hex> target=<summary> count=<n> age=<elapsed> same_exec=<0|1> logged=<0|1> [<tracee_domain|target_domain|peer_domain>=<hex>]
STATS domains=<allocated>/<total> denials=<n> (fs=<n> net=<n> ptrace=<n> signal=<n> abstract_unix=<n>)
```

`DENIAL` types are `FS`, `NET`, `PTRACE`, `SIGNAL`, and `ABSTRACT_UNIX`.
IDs are lowercase hexadecimal without `0x`; ruleset versions and all counters
are decimal. A root domain has `parent=0`, while `?` means the observer did not
learn the value. `tracee_domain`, `target_domain`, and `peer_domain` occur on
ptrace, signal, and abstract UNIX socket denials respectively; their value is
`0` when the tracee, target, or peer was unsandboxed.

Known blockers use kernel semantic names (`FS:read_file`,
`Net:connect_tcp`, `ptrace`, `Scope:signal`, or
`Scope:abstract_unix_socket`). Unknown access bits are retained as a lowercase
`0x` hexadecimal comma-separated component. Every target summary is one token.
Network targets are `sport:<port>` for unambiguous bind access and
`dport:<port>` for unambiguous connect/send access, including when the selected
port is zero. Both are shown as `sport:<port>,dport:<port>` when known access
names do not determine one direction. Filesystem targets are escaped paths,
task targets are `pid:<tgid>:<comm>`, and abstract UNIX targets are
`peer:<pid>`.

Every byte in a kernel-captured path or command that is not an ASCII letter,
digit, `_`, `-`, `.`, or `/` is encoded as `\xNN`, using exactly two lowercase
hexadecimal digits. This includes spaces, target separators captured within a
path or command, protocol punctuation, percent and backslash, control bytes, and
all non-ASCII bytes, so records cannot be split or terminal control sequences
injected. Fixed protocol punctuation is not escaped.

`count` is the saturating local aggregate count. `age` is the saturating elapsed
kernel monotonic time from the first to latest observation of that aggregate,
rendered as `Ns`, `NmNs`, or `NhNm`. The total and five per-kind denial counters
are independent saturating observed-event counters. Domain allocated/total
values come from reconstructed state; total includes unknown placeholders and
deallocated objects. Collection is partial as described by the root README, so
these values are observations rather than an audit log.

## Testing

Normal workspace test runs exercise formatting and protocol behavior without
loading BPF. The end-to-end `batch_integration` test is explicitly ignored
because it needs the fixed ABI 11 x86_64 guest and BPF privileges. It launches
the Cargo-built `lltop --batch` binary without a terminal, waits for
`LLTOP_READY`, and runs a hermetic Landlock scenario:

```console
./landlock-test-tools/x86-run.sh /path/to/bzImage -- \
  env LANDLOCK_CRATE_TEST_ABI=11 /path/to/batch_integration-test \
  --ignored --exact batch_integration --test-threads 1
```

A missing or different ABI value is an error. Running the ignored test directly
on a normal host is not supported. The fixed-kernel workflow builds and locates
the exact test once on the host. Cargo builds `lltop` for the integration test
and embeds its exact path, then the workflow invokes the test directly in a
fresh guest through the pinned x86 runner.
