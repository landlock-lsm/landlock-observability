#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build workspace documentation in a fresh target with Clang unavailable.
# This proves DOCS_RS bypasses BPF generation instead of reusing artifacts.

set -euo pipefail

if (( $# != 0 )); then
	printf 'Usage: %s\n' "$0" >&2
	exit 2
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/landlock-docsrs.XXXXXX")"
docs_target=$scratch/target
unavailable_tools=$scratch/tools
mkdir "$docs_target" "$unavailable_tools"
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
ln -s /bin/false "$unavailable_tools/clang"

cd -- "$source_dir"
DOCS_RS=1 \
	CLANG=/bin/false \
	CARGO_TARGET_DIR="$docs_target" \
	PATH="$unavailable_tools:$PATH" \
	rustup run stable cargo doc --locked --workspace --no-deps

mapfile -t bpf_artifacts < <(
	find "$docs_target" -type f \
		\( -name '*.bpf.o' -o -name '*.skel.rs' \) -print
)
if (( ${#bpf_artifacts[@]} != 0 )); then
	echo 'error: docs.rs documentation generated BPF artifacts:' >&2
	printf '  %s\n' "${bpf_artifacts[@]}" >&2
	exit 1
fi
