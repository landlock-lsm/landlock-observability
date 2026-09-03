#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Re-run the package build script for little- and big-endian targets.
# Check ELF EI_DATA so host byte order cannot silently select the BPF target.

set -u -e -o pipefail

if (( $# > 1 )); then
	printf 'Usage: %s [BUILD_SCRIPT_EXECUTABLE]\n' "$0" >&2
	exit 2
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
build_script=${1:-}
if [[ -z $build_script ]]; then
	target_dir=${CARGO_TARGET_DIR:-$source_dir/target}
	if [[ $target_dir != /* ]]; then
		target_dir=$source_dir/$target_dir
	fi
	build_dir=$target_dir/debug/build
	if [[ ! -d $build_dir ]]; then
		printf 'error: Cargo build directory not found: %s\n' "$build_dir" >&2
		exit 2
	fi
	mapfile -t build_scripts < <(
		find "$build_dir" -maxdepth 2 -type f -executable \
			-path '*/landlock-observability-*/build-script-build' \
			-printf '%T@ %p\n' | sort -rn
	)
	if (( ${#build_scripts[@]} == 0 )); then
		echo 'error: landlock-observability build script not found' >&2
		exit 2
	fi
	build_script=${build_scripts[0]#* }
fi
if [[ ! -f $build_script ]]; then
	printf 'error: build-script executable not found: %s\n' "$build_script" >&2
	exit 2
fi
if [[ ! -x $build_script ]]; then
	printf 'error: build-script argument is not executable: %s\n' "$build_script" >&2
	exit 2
fi

build_script=$(cd -- "$(dirname -- "$build_script")" && pwd -P)/$(basename -- "$build_script")
temp_root=$(mktemp -d -- "${TMPDIR:-/tmp}/check-bpf-endianness.XXXXXX")
cleanup()
{
	rm -rf -- "$temp_root"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
temp_root=$(cd -- "$temp_root" && pwd -P)

check_target()
{
	local arch=$1
	local endian=$2
	local expected_ei_data=$3
	local out_dir=$temp_root/$arch
	local object=$out_dir/landlock_observability.bpf.o
	local magic
	local ei_data
	local actual_endian

	mkdir -- "$out_dir"
	if ! (
		cd -- "$source_dir"
		env -u DOCS_RS \
			OUT_DIR="$out_dir" \
			CARGO_CFG_TARGET_ARCH="$arch" \
			CARGO_CFG_TARGET_ENDIAN="$endian" \
			"$build_script"
	); then
		printf 'error: build script failed for target %s (%s-endian)\n' \
			"$arch" "$endian" >&2
		return 1
	fi

	if [[ ! -f $object ]]; then
		printf 'error: build script did not create expected object: %s\n' \
			"$object" >&2
		return 1
	fi

	magic=$(od -An -tx1 -N4 -- "$object" | tr -d '[:space:]')
	if [[ $magic != 7f454c46 ]]; then
		printf 'error: build output is not an ELF object: %s\n' "$object" >&2
		return 1
	fi

	ei_data=$(od -An -tu1 -j5 -N1 -- "$object" | tr -d '[:space:]')
	case $ei_data in
	1)
		actual_endian=little
		;;
	2)
		actual_endian=big
		;;
	*)
		printf 'error: object has unknown or missing ELF EI_DATA byte: %s\n' \
			"$object" >&2
		return 1
		;;
	esac

	if [[ $ei_data != "$expected_ei_data" ]]; then
		printf 'error: %s target produced %s-endian ELF object; expected %s-endian (EI_DATA=%s)\n' \
			"$arch" "$actual_endian" "$endian" "$expected_ei_data" >&2
		return 1
	fi
}

check_target x86_64 little 1
check_target s390x big 2
