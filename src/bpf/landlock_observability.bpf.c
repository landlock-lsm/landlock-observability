// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock tracepoint programs sending fixed-size events to userspace.
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "event.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EVENT_RING_SIZE);
} events SEC(".maps");

static __always_inline void *alloc_event(void)
{
	struct landlock_observability_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event)
		__builtin_memset(event, 0, sizeof(*event));
	return event;
}

static __always_inline void submit_event(void *ev)
{
	bpf_ringbuf_submit(ev, 0);
}

/*
 * String-reading helpers reserve the last byte for NUL.  Read one extra byte
 * into zeroed stack storage so a full destination contains no NUL and the
 * userspace decoder can distinguish truncation from an exact short capture.
 */
static __always_inline bool capture_path(char dst[PATH_MAX_LEN],
					 const char *source)
{
	char buffer[PATH_MAX_LEN + 1];
	long length;

	__builtin_memset(buffer, 0, sizeof(buffer));
	length = bpf_probe_read_kernel_str(buffer, sizeof(buffer), source);
	if (length < 0)
		return 0;
	__builtin_memcpy(dst, buffer, PATH_MAX_LEN);
	return 1;
}

/*
 * Fill the common denial header fields from the hierarchy pointer.  This allows
 * userspace to reconstruct domain information after a missed create_domain
 * event (late start).
 */
static __always_inline void fill_deny_header(__u64 *domain_id, __u64 *parent_id,
					     __u32 *creator_tgid,
					     char *creator_comm,
					     __u64 *num_denials,
					     const struct landlock_hierarchy *h)
{
	const struct landlock_hierarchy *parent;
	const struct landlock_details *details;

	*domain_id = BPF_CORE_READ(h, id);
	*num_denials = BPF_CORE_READ(h, num_denials.counter);

	parent = BPF_CORE_READ(h, parent);
	*parent_id = parent ? BPF_CORE_READ(parent, id) : 0;
	details = BPF_CORE_READ(h, details);
	if (details) {
		const struct pid *pid_struct = BPF_CORE_READ(details, pid);

		*creator_tgid =
			pid_struct ? BPF_CORE_READ(pid_struct, numbers[0].nr) :
				     0;
		bpf_core_read_str(creator_comm, TASK_COMM_LEN, &details->comm);
	} else {
		*creator_tgid = 0;
		creator_comm[0] = '\0';
	}
}

SEC("tp_btf/landlock_create_ruleset")
int BPF_PROG(handle_create_ruleset, const struct landlock_ruleset *ruleset)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_CREATE_RULESET;
	ev->create_ruleset.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->create_ruleset.ruleset_version = BPF_CORE_READ(ruleset, version);
	ev->create_ruleset.handled_fs =
		BPF_CORE_READ_BITFIELD_PROBED(ruleset, handled_masks.fs);
	ev->create_ruleset.handled_net =
		BPF_CORE_READ_BITFIELD_PROBED(ruleset, handled_masks.net);
	ev->create_ruleset.scoped =
		BPF_CORE_READ_BITFIELD_PROBED(ruleset, handled_masks.scope);

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_add_rule_fs")
int BPF_PROG(handle_add_rule_fs, const struct landlock_ruleset *ruleset,
	     u32 access_rights, const struct path *path, const char *pathname)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_ADD_RULE_FS;
	ev->add_rule_fs.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->add_rule_fs.ruleset_version = BPF_CORE_READ(ruleset, version);
	ev->add_rule_fs.access_rights = access_rights;
	ev->add_rule_fs.dev = BPF_CORE_READ(path, dentry, d_sb, s_dev);
	ev->add_rule_fs.ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	if (!capture_path(ev->add_rule_fs.pathname, pathname)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_add_rule_net")
int BPF_PROG(handle_add_rule_net, const struct landlock_ruleset *ruleset,
	     u32 access_rights, u64 port)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_ADD_RULE_NET;
	ev->add_rule_net.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->add_rule_net.ruleset_version = BPF_CORE_READ(ruleset, version);
	ev->add_rule_net.access_rights = access_rights;
	ev->add_rule_net.port = port;

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_create_domain")
int BPF_PROG(handle_create_domain, const struct landlock_domain *new_dom,
	     const struct landlock_ruleset *ruleset)
{
	const struct landlock_hierarchy *parent;
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_CREATE_DOMAIN;
	ev->create_domain.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->create_domain.ruleset_version = BPF_CORE_READ(ruleset, version);
	ev->create_domain.domain_id = BPF_CORE_READ(new_dom, hierarchy, id);
	parent = BPF_CORE_READ(new_dom, hierarchy, parent);
	ev->create_domain.parent_id = parent ? BPF_CORE_READ(parent, id) : 0;
	ev->create_domain.creator_tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(ev->create_domain.creator_comm,
			     sizeof(ev->create_domain.creator_comm));

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_enforce_domain")
int BPF_PROG(handle_enforce_domain, const struct landlock_domain *domain,
	     bool complete, bool process_wide, bool no_new_privs)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_ENFORCE_DOMAIN;
	ev->enforce_domain.domain_id = BPF_CORE_READ(domain, hierarchy, id);
	/* The low 32 bits are the enforcing thread's TID. */
	ev->enforce_domain.enforcing_tid = (__u32)bpf_get_current_pid_tgid();
	ev->enforce_domain.complete = complete;
	ev->enforce_domain.process_wide = process_wide;
	ev->enforce_domain.no_new_privs = no_new_privs;

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_access_fs")
int BPF_PROG(handle_deny_access_fs, const struct landlock_hierarchy *hierarchy,
	     bool same_exec, bool logged, u32 blockers, const struct path *path,
	     const char *pathname)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_ACCESS_FS;
	fill_deny_header(&ev->deny_access_fs.domain_id,
			 &ev->deny_access_fs.parent_id,
			 &ev->deny_access_fs.creator_tgid,
			 ev->deny_access_fs.creator_comm,
			 &ev->deny_access_fs.num_denials, hierarchy);
	ev->deny_access_fs.blockers = blockers;
	ev->deny_access_fs.same_exec = same_exec;
	ev->deny_access_fs.logged = logged;
	ev->deny_access_fs.dev = BPF_CORE_READ(path, dentry, d_sb, s_dev);
	ev->deny_access_fs.ino = BPF_CORE_READ(path, dentry, d_inode, i_ino);
	if (!capture_path(ev->deny_access_fs.pathname, pathname)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_access_net")
int BPF_PROG(handle_deny_access_net, const struct landlock_hierarchy *hierarchy,
	     bool same_exec, bool logged, u32 blockers, const struct sock *sk,
	     __u64 sport, __u64 dport)
{
	struct landlock_observability_event *ev = alloc_event();

	(void)sk;
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_ACCESS_NET;
	fill_deny_header(&ev->deny_access_net.domain_id,
			 &ev->deny_access_net.parent_id,
			 &ev->deny_access_net.creator_tgid,
			 ev->deny_access_net.creator_comm,
			 &ev->deny_access_net.num_denials, hierarchy);
	ev->deny_access_net.blockers = blockers;
	ev->deny_access_net.same_exec = same_exec;
	ev->deny_access_net.logged = logged;
	ev->deny_access_net.sport = sport;
	ev->deny_access_net.dport = dport;

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_ptrace")
int BPF_PROG(handle_deny_ptrace, const struct landlock_hierarchy *hierarchy,
	     bool same_exec, bool logged, u64 tracee_domain_id,
	     const struct task_struct *tracee)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_PTRACE;
	fill_deny_header(&ev->deny_ptrace.domain_id, &ev->deny_ptrace.parent_id,
			 &ev->deny_ptrace.creator_tgid,
			 ev->deny_ptrace.creator_comm,
			 &ev->deny_ptrace.num_denials, hierarchy);
	/* No blockers field: the event name identifies the denial type. */
	ev->deny_ptrace.blockers = 0;
	ev->deny_ptrace.same_exec = same_exec;
	ev->deny_ptrace.logged = logged;
	ev->deny_ptrace.tracee_domain_id = tracee_domain_id;
	ev->deny_ptrace.tracee_pid = BPF_CORE_READ(tracee, tgid);
	BPF_CORE_READ_STR_INTO(&ev->deny_ptrace.tracee_comm, tracee, comm);

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_scope_signal")
int BPF_PROG(handle_deny_scope_signal,
	     const struct landlock_hierarchy *hierarchy, bool same_exec,
	     bool logged, u64 target_domain_id,
	     const struct task_struct *target)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_SCOPE_SIGNAL;
	fill_deny_header(&ev->deny_scope_signal.domain_id,
			 &ev->deny_scope_signal.parent_id,
			 &ev->deny_scope_signal.creator_tgid,
			 ev->deny_scope_signal.creator_comm,
			 &ev->deny_scope_signal.num_denials, hierarchy);
	ev->deny_scope_signal.blockers = 0;
	ev->deny_scope_signal.same_exec = same_exec;
	ev->deny_scope_signal.logged = logged;
	ev->deny_scope_signal.target_domain_id = target_domain_id;
	ev->deny_scope_signal.target_pid = BPF_CORE_READ(target, tgid);
	BPF_CORE_READ_STR_INTO(&ev->deny_scope_signal.target_comm, target,
			       comm);

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_scope_abstract_unix_socket")
int BPF_PROG(handle_deny_scope_abstract_unix_socket,
	     const struct landlock_hierarchy *hierarchy, bool same_exec,
	     bool logged, u64 peer_domain_id, const struct sock *peer)
{
	struct landlock_observability_event *ev = alloc_event();
	const struct pid *peer_pid;

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_SCOPE_ABSTRACT_UNIX_SOCKET;
	fill_deny_header(&ev->deny_scope_abstract_unix_socket.domain_id,
			 &ev->deny_scope_abstract_unix_socket.parent_id,
			 &ev->deny_scope_abstract_unix_socket.creator_tgid,
			 ev->deny_scope_abstract_unix_socket.creator_comm,
			 &ev->deny_scope_abstract_unix_socket.num_denials,
			 hierarchy);
	ev->deny_scope_abstract_unix_socket.blockers = 0;
	ev->deny_scope_abstract_unix_socket.same_exec = same_exec;
	ev->deny_scope_abstract_unix_socket.logged = logged;
	ev->deny_scope_abstract_unix_socket.peer_domain_id = peer_domain_id;
	peer_pid = BPF_CORE_READ(peer, sk_peer_pid);
	ev->deny_scope_abstract_unix_socket.peer_pid =
		peer_pid ? BPF_CORE_READ(peer_pid, numbers[0].nr) : 0;

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_free_domain")
int BPF_PROG(handle_free_domain, const struct landlock_hierarchy *hierarchy)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_FREE_DOMAIN;
	ev->free_domain.domain_id = BPF_CORE_READ(hierarchy, id);
	ev->free_domain.denials = BPF_CORE_READ(hierarchy, num_denials.counter);

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_free_ruleset")
int BPF_PROG(handle_free_ruleset, const struct landlock_ruleset *ruleset)
{
	struct landlock_observability_event *ev = alloc_event();

	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_FREE_RULESET;
	ev->free_ruleset.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->free_ruleset.ruleset_version = BPF_CORE_READ(ruleset, version);

	submit_event(ev);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
