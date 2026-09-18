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

static __always_inline void discard_event(void *ev)
{
	bpf_ringbuf_discard(ev, 0);
}

#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10

#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#define LANDLOCK_ACCESS_NET_BIND_UDP (1ULL << 2)
#define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP (1ULL << 3)

#define LANDLOCK_ACCESS_NET_BIND \
	(LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_BIND_UDP)
#define LANDLOCK_ACCESS_NET_CONNECT_SEND \
	(LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP)

#define SOCKADDR_PORT_END                                         \
	((int)(__builtin_offsetof(struct sockaddr_in, sin_port) + \
	       sizeof(((struct sockaddr_in *)0)->sin_port)))
#define HAS_CHECKED_PORT(addrlen, address_family, socket_family)         \
	((addrlen) >= SOCKADDR_PORT_END &&                               \
	 ((address_family) == AF_INET || (address_family) == AF_INET6 || \
	  ((address_family) == AF_UNSPEC && (socket_family) == AF_INET)))
#define LEGACY_SOURCE_PORT(access, has_port, port) \
	((has_port) && ((access) & LANDLOCK_ACCESS_NET_BIND) ? (port) : 0)
#define LEGACY_DESTINATION_PORT(access, has_port, port)                \
	((has_port) && ((access) & LANDLOCK_ACCESS_NET_CONNECT_SEND) ? \
		 (port) :                                              \
		 0)

_Static_assert(SOCKADDR_PORT_END == 4,
	       "update checked-port tests for a changed port layout");
_Static_assert(LEGACY_SOURCE_PORT(LANDLOCK_ACCESS_NET_BIND_TCP, 1, 7) == 7,
	       "bind access must project to source");
_Static_assert(LEGACY_DESTINATION_PORT(LANDLOCK_ACCESS_NET_CONNECT_TCP, 1, 7) ==
		       7,
	       "connect access must project to destination");
_Static_assert(LEGACY_DESTINATION_PORT(LANDLOCK_ACCESS_NET_CONNECT_TCP, 1, 0) ==
		       0,
	       "checked port zero must remain zero");
_Static_assert(LEGACY_SOURCE_PORT(LANDLOCK_ACCESS_NET_BIND_TCP, 0, 7) == 0 &&
		       LEGACY_DESTINATION_PORT(LANDLOCK_ACCESS_NET_CONNECT_TCP,
					       0, 7) == 0,
	       "an absent port must project to zero");
_Static_assert(LEGACY_SOURCE_PORT(1ULL << 63, 1, 7) == 0 &&
		       LEGACY_DESTINATION_PORT(1ULL << 63, 1, 7) == 0,
	       "unknown access must not guess a direction");
_Static_assert(HAS_CHECKED_PORT(4, AF_INET, AF_INET6),
	       "IPv4 addresses contain a port");
_Static_assert(HAS_CHECKED_PORT(4, AF_UNSPEC, AF_INET),
	       "IPv4 AF_UNSPEC addresses contain a port");
_Static_assert(!HAS_CHECKED_PORT(3, AF_INET, AF_INET),
	       "short addresses do not contain a port");
_Static_assert(!HAS_CHECKED_PORT(-1, AF_INET, AF_INET),
	       "negative lengths do not contain a port");
_Static_assert(!HAS_CHECKED_PORT(4, AF_UNSPEC, AF_INET6),
	       "IPv6 AF_UNSPEC addresses do not contain a port");

/*
 * Preserve the legacy source/destination projection until the semantic API
 * can represent the checked address directly.  Zero remains ambiguous with
 * an absent port.
 */
static __always_inline void
project_checked_port(__u64 blockers_access, u16 socket_family,
		     const struct sockaddr_storage *address, int addrlen,
		     __u64 *source_port, __u64 *destination_port)
{
	const struct sockaddr *sockaddr = (const struct sockaddr *)address;
	const u16 address_family = BPF_CORE_READ(sockaddr, sa_family);
	const bool has_port =
		HAS_CHECKED_PORT(addrlen, address_family, socket_family);
	__u64 port = 0;

	if (has_port)
		port = bpf_ntohs(BPF_CORE_READ(
			(const struct sockaddr_in *)address, sin_port));

	*source_port = LEGACY_SOURCE_PORT(blockers_access, has_port, port);
	*destination_port =
		LEGACY_DESTINATION_PORT(blockers_access, has_port, port);
}

/* Capture the abstract UNIX socket name, excluding its namespace NUL. */
static __always_inline bool
capture_abstract_unix_socket_name(char dst[ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN],
				  __u32 *dst_len, const struct sock *peer)
{
	/* unix_sk() is this cast: struct sock is unix_sock's first member. */
	const struct unix_sock *unix_peer = (const struct unix_sock *)peer;
	const struct unix_address *addr;
	const char *sun_path;
	const int prefix_len =
		(int)__builtin_offsetof(struct sockaddr_un, sun_path) + 1;
	char namespace;
	int sockaddr_len;
	__u32 name_len;

	addr = BPF_CORE_READ(unix_peer, addr);
	if (!addr) {
		*dst_len = 0;
		return 1;
	}

	/* No unknown API state: fabricating empty corrupts identity. */
	sockaddr_len = BPF_CORE_READ(addr, len);
	if (sockaddr_len < prefix_len ||
	    sockaddr_len > prefix_len + ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN)
		return 0;
	name_len = (__u32)(sockaddr_len - prefix_len);

	sun_path = __builtin_preserve_access_index(&addr->name[0].sun_path[0]);
	if (bpf_probe_read_kernel(&namespace, sizeof(namespace), sun_path))
		return 0;
	if (namespace != '\0')
		return 0;
	if (name_len && bpf_probe_read_kernel(dst, name_len, sun_path + 1))
		return 0;

	*dst_len = name_len;
	return 1;
}

/*
 * Read two bytes beyond the payload boundary.  The returned length includes
 * NUL, so PATH_MAX_LEN + 1 is an exact-fit source while a larger result proves
 * that source bytes were omitted from the event.
 */
static __always_inline bool
capture_path(char dst[PATH_MAX_LEN], __u8 *bytes_omitted, const char *source)
{
	char buffer[PATH_MAX_LEN + 2];
	long length;

	__builtin_memset(buffer, 0, sizeof(buffer));
	length = bpf_probe_read_kernel_str(buffer, sizeof(buffer), source);
	if (length < 0)
		return 0;
	__builtin_memcpy(dst, buffer, PATH_MAX_LEN);
	*bytes_omitted = length > PATH_MAX_LEN + 1;
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
	/*
	 * Successful domain creation guarantees details and a referenced TGID.
	 * Keep the null checks for safe BPF pointer chasing; userspace rejects
	 * a defensive zero creator TGID as a malformed sample.
	 */
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

SEC("tp_btf/landlock_add_rule_path_beneath")
int BPF_PROG(handle_add_rule_path_beneath,
	     const struct landlock_ruleset *ruleset, u32 flags,
	     u64 access_rights, const struct path *path, const char *pathname)
{
	struct landlock_observability_event *ev = alloc_event();

	(void)flags;
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_ADD_RULE_PATH_BENEATH;
	ev->add_rule_path_beneath.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->add_rule_path_beneath.ruleset_version =
		BPF_CORE_READ(ruleset, version);
	ev->add_rule_path_beneath.access_rights = access_rights;
	ev->add_rule_path_beneath.dev =
		BPF_CORE_READ(path, dentry, d_sb, s_dev);
	ev->add_rule_path_beneath.ino =
		BPF_CORE_READ(path, dentry, d_inode, i_ino);
	if (!capture_path(ev->add_rule_path_beneath.pathname,
			  &ev->add_rule_path_beneath.pathname_bytes_omitted,
			  pathname)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_add_rule_net_port")
int BPF_PROG(handle_add_rule_net_port, const struct landlock_ruleset *ruleset,
	     u32 flags, u64 access_rights, u64 port)
{
	struct landlock_observability_event *ev = alloc_event();

	(void)flags;
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_ADD_RULE_NET_PORT;
	ev->add_rule_net_port.ruleset_id = BPF_CORE_READ(ruleset, id);
	ev->add_rule_net_port.ruleset_version = BPF_CORE_READ(ruleset, version);
	ev->add_rule_net_port.access_rights = access_rights;
	ev->add_rule_net_port.port = port;

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
	     bool same_exec, bool logged,
	     const struct landlock_blockers *blockers, const struct path *path,
	     const char *pathname)
{
	const struct inode *inode;
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
	ev->deny_access_fs.blockers_access = blockers->access;
	ev->deny_access_fs.same_exec = same_exec;
	ev->deny_access_fs.logged = logged;
	ev->deny_access_fs.dev = BPF_CORE_READ(path, dentry, d_sb, s_dev);
	inode = BPF_CORE_READ(path, dentry, d_inode);
	ev->deny_access_fs.ino = inode ? BPF_CORE_READ(inode, i_ino) : 0;
	if (!capture_path(ev->deny_access_fs.pathname,
			  &ev->deny_access_fs.pathname_bytes_omitted,
			  pathname)) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_access_net")
int BPF_PROG(handle_deny_access_net, const struct landlock_hierarchy *hierarchy,
	     bool same_exec, bool logged,
	     const struct landlock_blockers *blockers, const struct sock *sk,
	     u16 socket_family, const struct sockaddr_storage *address,
	     int addrlen)
{
	const __u64 blockers_access = blockers->access;
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
	ev->deny_access_net.blockers_access = blockers_access;
	ev->deny_access_net.same_exec = same_exec;
	ev->deny_access_net.logged = logged;
	project_checked_port(blockers_access, socket_family, address, addrlen,
			     &ev->deny_access_net.sport,
			     &ev->deny_access_net.dport);

	submit_event(ev);
	return 0;
}

SEC("tp_btf/landlock_deny_ptrace")
int BPF_PROG(handle_deny_ptrace, const struct landlock_hierarchy *hierarchy,
	     bool same_exec, bool logged, u64 tracee_domain_id,
	     const struct task_struct *tracee, const struct task_struct *tracer)
{
	struct landlock_observability_event *ev = alloc_event();

	(void)tracer;
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_PTRACE;
	fill_deny_header(&ev->deny_ptrace.domain_id, &ev->deny_ptrace.parent_id,
			 &ev->deny_ptrace.creator_tgid,
			 ev->deny_ptrace.creator_comm,
			 &ev->deny_ptrace.num_denials, hierarchy);
	/* No blockers field: the event name identifies the denial type. */
	ev->deny_ptrace.blockers_access = 0;
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
	     const struct task_struct *target, int signal)
{
	struct landlock_observability_event *ev = alloc_event();

	(void)signal;
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_SCOPE_SIGNAL;
	fill_deny_header(&ev->deny_scope_signal.domain_id,
			 &ev->deny_scope_signal.parent_id,
			 &ev->deny_scope_signal.creator_tgid,
			 ev->deny_scope_signal.creator_comm,
			 &ev->deny_scope_signal.num_denials, hierarchy);
	ev->deny_scope_signal.blockers_access = 0;
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
	struct landlock_observability_event *ev;
	const struct pid *peer_pid;

	ev = alloc_event();
	if (!ev)
		return 0;
	if (!capture_abstract_unix_socket_name(
		    ev->deny_scope_abstract_unix_socket.abstract_name,
		    &ev->deny_scope_abstract_unix_socket.abstract_name_len,
		    peer)) {
		discard_event(ev);
		return 0;
	}

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type = EVENT_DENY_SCOPE_ABSTRACT_UNIX_SOCKET;
	fill_deny_header(&ev->deny_scope_abstract_unix_socket.domain_id,
			 &ev->deny_scope_abstract_unix_socket.parent_id,
			 &ev->deny_scope_abstract_unix_socket.creator_tgid,
			 ev->deny_scope_abstract_unix_socket.creator_comm,
			 &ev->deny_scope_abstract_unix_socket.num_denials,
			 hierarchy);
	ev->deny_scope_abstract_unix_socket.blockers_access = 0;
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
