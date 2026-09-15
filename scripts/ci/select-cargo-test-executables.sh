#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Select exact Cargo test executables from compiler-artifact JSON messages.
# This avoids guessing hashed paths and fails on missing or ambiguous targets.

set -euo pipefail

usage()
{
	printf 'Usage: %s CARGO_JSON TARGET=VARIABLE [TARGET=VARIABLE...]\n' \
		"$0" >&2
	exit 2
}

if (( $# < 2 )); then
	usage
fi

messages=$1
shift

if [[ ! -f $messages || ! -r $messages ]]; then
	printf 'Cargo messages are not a readable file: %s\n' "$messages" >&2
	exit 1
fi
if ! command -v jq >/dev/null; then
	printf 'jq is required to select Cargo test executables\n' >&2
	exit 1
fi

targets=()
variables=()
assignments=()

for mapping; do
	if [[ $mapping != *=* ]]; then
		printf 'Invalid target mapping: %s\n' "$mapping" >&2
		usage
	fi

	target=${mapping%%=*}
	variable=${mapping#*=}
	if [[ -z $target || $target == *$'\n'* || $target == *$'\r'* ]]; then
		printf 'Invalid Cargo target name in mapping: %s\n' "$mapping" >&2
		exit 2
	fi
	if [[ ! $variable =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
		printf 'Invalid variable name in mapping: %s\n' "$mapping" >&2
		exit 2
	fi

	for existing in "${targets[@]}"; do
		if [[ $existing == "$target" ]]; then
			printf 'Duplicate Cargo target mapping: %s\n' "$target" >&2
			exit 2
		fi
	done
	for existing in "${variables[@]}"; do
		if [[ $existing == "$variable" ]]; then
			printf 'Duplicate variable mapping: %s\n' "$variable" >&2
			exit 2
		fi
	done
	targets+=("$target")
	variables+=("$variable")

	executable=$(jq --exit-status --raw-output --slurp \
		--arg target "$target" '
		[
			.[] |
			select(
				.reason == "compiler-artifact" and
				.target.name == $target and
				.target.kind == ["test"] and
				.executable != null
			) |
			.executable
		] as $executables |
		if ($executables | length) == 1 then
			$executables[0]
		else
			error(
				"expected one \($target) executable, found " +
				"\($executables | length)"
			)
		end
	' "$messages")
	if [[ $executable == *$'\n'* || $executable == *$'\r'* ||
		! -f $executable || ! -x $executable ]]; then
		printf 'Invalid %s executable: %s\n' \
			"$target" "$executable" >&2
		exit 1
	fi
	assignments+=("$variable=$executable")
done

printf '%s\n' "${assignments[@]}"
