/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal BTF type definitions for Landlock observability BPF programs.
 *
 * This header provides the subset of kernel types needed by the BPF programs to
 * read Landlock tracepoint arguments via BTF/CO-RE.  It replaces the full
 * vmlinux.h to avoid dependency on a specific kernel build.
 *
 * CO-RE relocates these declarations against the running kernel's BTF.  The
 * maintenance verifier checks that every declared type and field exists in a
 * selected BTF-enabled kernel.
 */

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef _Bool bool;

/* Byte-order and checksum types for BPF helper prototypes. */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

/* Stubs for BPF helper prototypes that reference network types. */
struct tcphdr;
struct bpf_sock_tuple;

/* BPF map type (needed by map definitions). */
enum bpf_map_type {
	BPF_MAP_TYPE_RINGBUF = 27,
};

/*
 * Landlock internal structs (accessed via BPF_CORE_READ).  Only the fields
 * actually read by the BPF programs are declared; the rest are omitted.  CO-RE
 * handles field relocation.
 */

struct landlock_details {
	struct pid *pid;
	char comm[16];
} __attribute__((preserve_access_index));

struct atomic64 {
	long counter;
} __attribute__((preserve_access_index));

struct landlock_hierarchy {
	struct landlock_hierarchy *parent;
	u64 id;
	struct atomic64 num_denials;
	const struct landlock_details *details;
} __attribute__((preserve_access_index));

struct landlock_domain {
	struct landlock_hierarchy *hierarchy;
} __attribute__((preserve_access_index));

struct landlock_blockers {
	u32 access;
} __attribute__((preserve_access_index));

/*
 * Packed bitfield matching the kernel: fs/net/scope share one u32.  Read with
 * BPF_CORE_READ_BITFIELD_PROBED() so CO-RE relocates the bit offsets from the
 * running kernel's BTF.
 */
struct access_masks {
	u32 fs : 17;
	u32 net : 4;
	u32 scope : 2;
} __attribute__((packed, aligned(4), preserve_access_index));

struct landlock_ruleset {
	u64 id;
	u64 version;
	struct access_masks handled_masks;
} __attribute__((preserve_access_index));

/* Filesystem types. */
struct super_block {
	u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
} __attribute__((preserve_access_index));

struct dentry {
	struct super_block *d_sb;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

struct path {
	struct dentry *dentry;
} __attribute__((preserve_access_index));

/* Task types. */
struct task_struct {
	int tgid;
	char comm[16];
} __attribute__((preserve_access_index));

/* Network types. */
struct sockaddr {
	u16 sa_family;
} __attribute__((preserve_access_index));

struct sockaddr_in {
	u16 sin_family;
	__be16 sin_port;
} __attribute__((preserve_access_index));

struct sockaddr_storage;

struct upid {
	int nr;
} __attribute__((preserve_access_index));

struct pid {
	struct upid numbers[1];
} __attribute__((preserve_access_index));

struct sock {
	struct pid *sk_peer_pid;
} __attribute__((preserve_access_index));

struct sockaddr_un {
	unsigned short sun_family;
	char sun_path[108];
} __attribute__((preserve_access_index));

struct unix_address {
	int len;
	struct sockaddr_un name[];
} __attribute__((preserve_access_index));

struct unix_sock {
	struct sock sk;
	struct unix_address *addr;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
