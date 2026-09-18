/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LANDLOCK_OBSERVABILITY_EVENT_H
#define LANDLOCK_OBSERVABILITY_EVENT_H

/* Kernel command sources are NUL-terminated TASK_COMM_LEN arrays. */
#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
/* sun_path capacity minus the structural abstract-namespace NUL. */
#define ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN 107
#define EVENT_RING_SIZE (256 * 1024)

enum event_type {
	EVENT_CREATE_RULESET = 1,
	EVENT_ADD_RULE_PATH_BENEATH,
	EVENT_ADD_RULE_NET_PORT,
	EVENT_CREATE_DOMAIN,
	EVENT_DENY_ACCESS_FS,
	EVENT_DENY_ACCESS_NET,
	EVENT_DENY_PTRACE,
	EVENT_DENY_SCOPE_SIGNAL,
	EVENT_DENY_SCOPE_ABSTRACT_UNIX_SOCKET,
	EVENT_FREE_DOMAIN,
	EVENT_FREE_RULESET,
	EVENT_ENFORCE_DOMAIN,
};

struct landlock_observability_event {
	__u64 timestamp_ns;
	__u8 type;
	__u8 _pad[3];
	__u8 _union_pad[4];
	union {
		struct {
			__u64 ruleset_id;
			__u64 ruleset_version;
			__u64 handled_fs;
			__u64 handled_net;
			__u64 scoped;
		} create_ruleset;
		struct {
			__u64 ruleset_id;
			__u64 ruleset_version;
			__u64 access_rights;
			__u32 dev;
			__u8 pathname_bytes_omitted;
			__u8 _ino_pad[3];
			__u64 ino;
			char pathname[PATH_MAX_LEN];
		} add_rule_path_beneath;
		struct {
			__u64 ruleset_id;
			__u64 ruleset_version;
			__u64 access_rights;
			__u64 port;
		} add_rule_net_port;
		struct {
			__u64 ruleset_id;
			__u64 ruleset_version;
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _tail_pad[4];
		} create_domain;
		struct {
			__u64 domain_id;
			__u32 enforcing_tid;
			__u8 complete;
			__u8 process_wide;
			__u8 no_new_privs;
			__u8 _pad[1];
		} enforce_domain;
		struct {
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _count_pad[4];
			__u64 num_denials;
			__u64 blockers_access;
			__u8 same_exec;
			__u8 logged;
			__u8 _pad[6];
			__u32 dev;
			__u8 pathname_bytes_omitted;
			__u8 _ino_pad[3];
			__u64 ino;
			char pathname[PATH_MAX_LEN];
		} deny_access_fs;
		struct {
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _count_pad[4];
			__u64 num_denials;
			__u64 blockers_access;
			__u8 same_exec;
			__u8 logged;
			__u8 _pad[6];
			__u64 sport;
			__u64 dport;
		} deny_access_net;
		struct {
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _count_pad[4];
			__u64 num_denials;
			__u64 blockers_access;
			__u8 same_exec;
			__u8 logged;
			__u8 _pad[6];
			__u64 tracee_domain_id;
			__u32 tracee_pid;
			char tracee_comm[TASK_COMM_LEN];
			__u8 _tail_pad[4];
		} deny_ptrace;
		struct {
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _count_pad[4];
			__u64 num_denials;
			__u64 blockers_access;
			__u8 same_exec;
			__u8 logged;
			__u8 _pad[6];
			__u64 target_domain_id;
			__u32 target_pid;
			char target_comm[TASK_COMM_LEN];
			__u8 _tail_pad[4];
		} deny_scope_signal;
		struct {
			__u64 domain_id;
			__u64 parent_id;
			__u32 creator_tgid;
			char creator_comm[TASK_COMM_LEN];
			__u8 _count_pad[4];
			__u64 num_denials;
			__u64 blockers_access;
			__u8 same_exec;
			__u8 logged;
			__u8 _pad[6];
			__u64 peer_domain_id;
			__u32 peer_pid;
			__u32 abstract_name_len;
			char abstract_name[ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN];
			__u8 _tail_pad[5];
		} deny_scope_abstract_unix_socket;
		struct {
			__u64 domain_id;
			__u64 denials;
		} free_domain;
		struct {
			__u64 ruleset_id;
			__u64 ruleset_version;
		} free_ruleset;
	};
};

#define ASSERT_FIELD(member, expected_offset, expected_size)                   \
	_Static_assert(__builtin_offsetof(struct landlock_observability_event, \
					  member) == (expected_offset),        \
		       "unexpected offset: " #member);                         \
	_Static_assert(                                                        \
		sizeof(((struct landlock_observability_event *)0)->member) ==  \
			(expected_size),                                       \
		"unexpected size: " #member)

_Static_assert(EVENT_CREATE_RULESET == 1, "unexpected create-ruleset kind");
_Static_assert(EVENT_ADD_RULE_PATH_BENEATH == 2, "unexpected add-fs-rule kind");
_Static_assert(EVENT_ADD_RULE_NET_PORT == 3,
	       "unexpected add-network-rule kind");
_Static_assert(EVENT_CREATE_DOMAIN == 4, "unexpected create-domain kind");
_Static_assert(EVENT_DENY_ACCESS_FS == 5, "unexpected filesystem-denial kind");
_Static_assert(EVENT_DENY_ACCESS_NET == 6, "unexpected network-denial kind");
_Static_assert(EVENT_DENY_PTRACE == 7, "unexpected ptrace-denial kind");
_Static_assert(EVENT_DENY_SCOPE_SIGNAL == 8, "unexpected signal-denial kind");
_Static_assert(EVENT_DENY_SCOPE_ABSTRACT_UNIX_SOCKET == 9,
	       "unexpected abstract-UNIX-denial kind");
_Static_assert(EVENT_FREE_DOMAIN == 10, "unexpected free-domain kind");
_Static_assert(EVENT_FREE_RULESET == 11, "unexpected free-ruleset kind");
_Static_assert(EVENT_ENFORCE_DOMAIN == 12, "unexpected enforce-domain kind");
_Static_assert(sizeof(__u8) == 1, "unexpected __u8 width");
_Static_assert(sizeof(__u32) == 4, "unexpected __u32 width");
_Static_assert(sizeof(__u64) == 8, "unexpected __u64 width");
_Static_assert(sizeof(char) == 1, "unexpected char width");
_Static_assert(ABSTRACT_UNIX_SOCKET_NAME_MAX_LEN ==
		       sizeof(((struct sockaddr_un *)0)->sun_path) - 1,
	       "unexpected abstract UNIX socket name capacity");
_Static_assert(sizeof(struct landlock_observability_event) == 352,
	       "unexpected event size");
_Static_assert(__alignof__(struct landlock_observability_event) == 8,
	       "unexpected event alignment");
_Static_assert(__builtin_offsetof(struct landlock_observability_event,
				  create_ruleset) == 16,
	       "unexpected event union base");
ASSERT_FIELD(timestamp_ns, 0, 8);
ASSERT_FIELD(type, 8, 1);
ASSERT_FIELD(_pad, 9, 3);
ASSERT_FIELD(_union_pad, 12, 4);
ASSERT_FIELD(create_ruleset.ruleset_id, 16, 8);
ASSERT_FIELD(create_ruleset.ruleset_version, 24, 8);
ASSERT_FIELD(create_ruleset.handled_fs, 32, 8);
ASSERT_FIELD(create_ruleset.handled_net, 40, 8);
ASSERT_FIELD(create_ruleset.scoped, 48, 8);
ASSERT_FIELD(add_rule_path_beneath.ruleset_id, 16, 8);
ASSERT_FIELD(add_rule_path_beneath.ruleset_version, 24, 8);
ASSERT_FIELD(add_rule_path_beneath.access_rights, 32, 8);
ASSERT_FIELD(add_rule_path_beneath.dev, 40, 4);
ASSERT_FIELD(add_rule_path_beneath.pathname_bytes_omitted, 44, 1);
ASSERT_FIELD(add_rule_path_beneath._ino_pad, 45, 3);
ASSERT_FIELD(add_rule_path_beneath.ino, 48, 8);
ASSERT_FIELD(add_rule_path_beneath.pathname, 56, 256);
ASSERT_FIELD(add_rule_net_port.ruleset_id, 16, 8);
ASSERT_FIELD(add_rule_net_port.ruleset_version, 24, 8);
ASSERT_FIELD(add_rule_net_port.access_rights, 32, 8);
ASSERT_FIELD(add_rule_net_port.port, 40, 8);
ASSERT_FIELD(create_domain.ruleset_id, 16, 8);
ASSERT_FIELD(create_domain.ruleset_version, 24, 8);
ASSERT_FIELD(create_domain.domain_id, 32, 8);
ASSERT_FIELD(create_domain.parent_id, 40, 8);
ASSERT_FIELD(create_domain.creator_tgid, 48, 4);
ASSERT_FIELD(create_domain.creator_comm, 52, 16);
ASSERT_FIELD(create_domain._tail_pad, 68, 4);
ASSERT_FIELD(enforce_domain.domain_id, 16, 8);
ASSERT_FIELD(enforce_domain.enforcing_tid, 24, 4);
ASSERT_FIELD(enforce_domain.complete, 28, 1);
ASSERT_FIELD(enforce_domain.process_wide, 29, 1);
ASSERT_FIELD(enforce_domain.no_new_privs, 30, 1);
ASSERT_FIELD(enforce_domain._pad, 31, 1);
#define ASSERT_DENIAL_HEADER(variant)                 \
	ASSERT_FIELD(variant.domain_id, 16, 8);       \
	ASSERT_FIELD(variant.parent_id, 24, 8);       \
	ASSERT_FIELD(variant.creator_tgid, 32, 4);    \
	ASSERT_FIELD(variant.creator_comm, 36, 16);   \
	ASSERT_FIELD(variant._count_pad, 52, 4);      \
	ASSERT_FIELD(variant.num_denials, 56, 8);     \
	ASSERT_FIELD(variant.blockers_access, 64, 8); \
	ASSERT_FIELD(variant.same_exec, 72, 1);       \
	ASSERT_FIELD(variant.logged, 73, 1);          \
	ASSERT_FIELD(variant._pad, 74, 6)
ASSERT_DENIAL_HEADER(deny_access_fs);
ASSERT_FIELD(deny_access_fs.dev, 80, 4);
ASSERT_FIELD(deny_access_fs.pathname_bytes_omitted, 84, 1);
ASSERT_FIELD(deny_access_fs._ino_pad, 85, 3);
ASSERT_FIELD(deny_access_fs.ino, 88, 8);
ASSERT_FIELD(deny_access_fs.pathname, 96, 256);
ASSERT_DENIAL_HEADER(deny_access_net);
ASSERT_FIELD(deny_access_net.sport, 80, 8);
ASSERT_FIELD(deny_access_net.dport, 88, 8);
ASSERT_DENIAL_HEADER(deny_ptrace);
ASSERT_FIELD(deny_ptrace.tracee_domain_id, 80, 8);
ASSERT_FIELD(deny_ptrace.tracee_pid, 88, 4);
ASSERT_FIELD(deny_ptrace.tracee_comm, 92, 16);
ASSERT_FIELD(deny_ptrace._tail_pad, 108, 4);
ASSERT_DENIAL_HEADER(deny_scope_signal);
ASSERT_FIELD(deny_scope_signal.target_domain_id, 80, 8);
ASSERT_FIELD(deny_scope_signal.target_pid, 88, 4);
ASSERT_FIELD(deny_scope_signal.target_comm, 92, 16);
ASSERT_FIELD(deny_scope_signal._tail_pad, 108, 4);
ASSERT_DENIAL_HEADER(deny_scope_abstract_unix_socket);
ASSERT_FIELD(deny_scope_abstract_unix_socket.peer_domain_id, 80, 8);
ASSERT_FIELD(deny_scope_abstract_unix_socket.peer_pid, 88, 4);
ASSERT_FIELD(deny_scope_abstract_unix_socket.abstract_name_len, 92, 4);
ASSERT_FIELD(deny_scope_abstract_unix_socket.abstract_name, 96, 107);
ASSERT_FIELD(deny_scope_abstract_unix_socket._tail_pad, 203, 5);
ASSERT_FIELD(free_domain.domain_id, 16, 8);
ASSERT_FIELD(free_domain.denials, 24, 8);
ASSERT_FIELD(free_ruleset.ruleset_id, 16, 8);
ASSERT_FIELD(free_ruleset.ruleset_version, 24, 8);
ASSERT_FIELD(create_ruleset, 16, 40);
ASSERT_FIELD(add_rule_path_beneath, 16, 296);
ASSERT_FIELD(add_rule_net_port, 16, 32);
ASSERT_FIELD(create_domain, 16, 56);
ASSERT_FIELD(enforce_domain, 16, 16);
ASSERT_FIELD(deny_access_fs, 16, 336);
ASSERT_FIELD(deny_access_net, 16, 80);
ASSERT_FIELD(deny_ptrace, 16, 96);
ASSERT_FIELD(deny_scope_signal, 16, 96);
ASSERT_FIELD(deny_scope_abstract_unix_socket, 16, 192);
ASSERT_FIELD(free_domain, 16, 16);
ASSERT_FIELD(free_ruleset, 16, 16);

#undef ASSERT_DENIAL_HEADER
#undef ASSERT_FIELD

#endif /* LANDLOCK_OBSERVABILITY_EVENT_H */
