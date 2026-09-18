#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Check the compiled, pre-relocation access-mask load and storage shape.

set -e -u -o pipefail

if [[ $# != 2 || $1 != --bpf-object ]]; then
	echo "usage: ${BASH_SOURCE[0]} --bpf-object FILE" >&2
	exit 2
fi
object=$2
if [[ ! -r $object ]]; then
	printf 'error: unreadable BPF object: %s\n' "$object" >&2
	exit 2
fi

objdump=
for candidate in llvm-objdump /usr/lib/llvm-20/bin/llvm-objdump \
	/usr/lib/llvm-19/bin/llvm-objdump /usr/lib/llvm-18/bin/llvm-objdump; do
	if command -v "$candidate" >/dev/null 2>&1; then
		objdump=$(command -v "$candidate")
		break
	fi
done
if [[ -z $objdump ]]; then
	echo "error: llvm-objdump is required" >&2
	exit 2
fi

dump=$("$objdump" --source "$object")

check_direct_u64_load()
{
	local marker=$1
	local excerpt
	excerpt=$(grep -F -A2 "$marker" <<<"$dump")
	if ! grep -Eq '= \*\(u64 \*\)\(r[0-9]+ \+ 0x0\)$' <<<"$excerpt"; then
		printf 'error: no direct u64 field load after %s\n%s\n' \
			"$marker" "$excerpt" >&2
		exit 1
	fi
}

check_u64_store()
{
	local marker=$1
	local offset=$2
	local excerpt
	excerpt=$(grep -F -A2 "$marker" <<<"$dump")
	if ! grep -Eq "\\*\\(u64 \\*\\)\\(r[0-9]+ \\+ $offset\\) = r[0-9]+$" \
		<<<"$excerpt"; then
		printf 'error: no u64 wire store at %s after %s\n%s\n' \
			"$offset" "$marker" "$excerpt" >&2
		exit 1
	fi
}

check_ruleset_version_reads()
{
	local marker='BPF_CORE_READ(ruleset, version);'
	local excerpt
	local count
	excerpt=$(grep -F -A1 "$marker" <<<"$dump")
	count=$(grep -Ec 'r2 = 0x8$' <<<"$excerpt")
	if [[ $count != 5 ]]; then
		printf 'error: expected five u64 CO-RE ruleset-version reads, found %s\n%s\n' \
			"$count" "$excerpt" >&2
		exit 1
	fi
}

check_bitfield_read()
{
	local field=$1
	local marker="BPF_CORE_READ_BITFIELD_PROBED(ruleset, handled_masks.$field);"
	local destination
	if [[ $field == scope ]]; then
		destination='ev->create_ruleset.scoped ='
	else
		destination="ev->create_ruleset.handled_$field ="
	fi
	local excerpt
	excerpt=$(awk -v start="$marker" -v end="$destination" '
		!found && index($0, start) { found = 1 }
		found {
			print
			if (index($0, end))
				exit
		}
	' <<<"$dump")
	if [[ $excerpt != *"$destination"* || $excerpt != *'call '* || \
		$excerpt != *'<<='* || $excerpt != *'>>='* ]]; then
		printf 'error: no compiled probed bitfield read for %s\n%s\n' \
			"$field" "$excerpt" >&2
		exit 1
	fi
}

check_ruleset_version_reads
check_u64_store \
	'ev->create_ruleset.ruleset_version = BPF_CORE_READ(ruleset, version);' 0x18
check_u64_store 'ev->add_rule_path_beneath.ruleset_version =' 0x18
check_u64_store \
	'ev->add_rule_net_port.ruleset_version = BPF_CORE_READ(ruleset, version);' 0x18
check_u64_store \
	'ev->create_domain.ruleset_version = BPF_CORE_READ(ruleset, version);' 0x18
check_u64_store \
	'ev->free_ruleset.ruleset_version = BPF_CORE_READ(ruleset, version);' 0x18

check_direct_u64_load 'ev->deny_access_fs.blockers_access = blockers->access;'
check_direct_u64_load 'const __u64 blockers_access = blockers->access;'

check_u64_store 'ev->create_ruleset.handled_fs =' 0x20
check_u64_store 'ev->create_ruleset.handled_net =' 0x28
check_u64_store 'ev->create_ruleset.scoped =' 0x30
check_u64_store 'ev->add_rule_path_beneath.access_rights = access_rights;' 0x20
check_u64_store 'ev->add_rule_net_port.access_rights = access_rights;' 0x20
check_u64_store 'ev->deny_access_fs.blockers_access = blockers->access;' 0x40
check_u64_store 'ev->deny_access_net.blockers_access = blockers_access;' 0x40

check_bitfield_read fs
check_bitfield_read net
check_bitfield_read scope
