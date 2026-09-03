#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Validate generated BPF CO-RE requirements against an explicit kernel BTF.
# This catches declarations that cannot relocate on the tested kernel.

set -u -e -o pipefail

usage()
{
	cat <<'EOF'
Usage: scripts/ci/check-core-declarations.sh --vmlinux FILE \
       (--bpf-object FILE | --build-dir DIR) [--dump]

Generate the minimal CO-RE BTF in a temporary directory.  A build directory
checks every landlock-observability BPF object beneath it.  --dump writes C
declarations to standard output for review.  No committed file is edited.
EOF
}

vmlinux=
bpf_object=
build_dir=
dump=false
while (($#)); do
	case "$1" in
	--help)
		usage
		exit 0
		;;
	--vmlinux | --bpf-object | --build-dir)
		if (($# < 2)); then
			echo "error: $1 requires a path" >&2
			usage >&2
			exit 2
		fi
		case "$1" in
		--vmlinux)
			vmlinux=$2
			;;
		--bpf-object)
			bpf_object=$2
			;;
		--build-dir)
			build_dir=$2
			;;
		esac
		shift 2
		;;
	--dump)
		dump=true
		shift
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

if [[ -z $vmlinux || ( -z $bpf_object && -z $build_dir ) ||
	( -n $bpf_object && -n $build_dir ) ]]; then
	echo "error: --vmlinux and exactly one object source are required" >&2
	usage >&2
	exit 2
fi
if [[ -n $build_dir ]]; then
	if [[ ! -d $build_dir ]]; then
		printf 'error: build directory not found: %s\n' "$build_dir" >&2
		exit 2
	fi
	mapfile -t bpf_objects < <(
		find "$build_dir" -type f \
			-name landlock_observability.bpf.o -print
	)
	if (( ${#bpf_objects[@]} == 0 )); then
		printf 'error: no BPF object found beneath: %s\n' "$build_dir" >&2
		exit 1
	fi
	for object in "${bpf_objects[@]}"; do
		arguments=(--vmlinux "$vmlinux" --bpf-object "$object")
		if [[ $dump == true ]]; then
			arguments+=(--dump)
		fi
		"${BASH_SOURCE[0]}" "${arguments[@]}"
	done
	exit 0
fi
if [[ ! -f $vmlinux || ! -r $vmlinux ]]; then
	echo "error: vmlinux is not a readable regular file: $vmlinux" >&2
	exit 2
fi
if [[ ! -f $bpf_object || ! -r $bpf_object ]]; then
	echo "error: BPF object is not a readable regular file: $bpf_object" >&2
	exit 2
fi
if ! command -v bpftool >/dev/null 2>&1; then
	echo "error: bpftool is required" >&2
	exit 2
fi
bpftool_help=$(bpftool gen help 2>&1 || true)
if [[ $bpftool_help != *"min_core_btf"* ]]; then
	echo "error: bpftool does not support gen min_core_btf" >&2
	exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/landlock-core-declarations.XXXXXX")
cleanup()
{
	rm -rf -- "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
minimal_btf=$tmp_dir/minimal.btf

bpftool gen min_core_btf "$vmlinux" "$minimal_btf" "$bpf_object"
if [[ $dump == true ]]; then
	bpftool btf dump file "$minimal_btf" format c
fi
