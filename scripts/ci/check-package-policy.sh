#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Validate development publication metadata for every workspace package.
# This keeps package versions, MSRV, and internal requirements synchronized.

set -euo pipefail

rustup run stable cargo metadata --locked --no-deps --format-version 1 |
	jq -e '
		([.packages[].rust_version] | unique) as $msrvs |
		([.packages[].version] | unique) == ["0.0.0"] and
		($msrvs | length) == 1 and
		($msrvs[0] != null) and
		(
			([.packages[] | select(.name == "lltop")] | length) == 0 or
			([
				.packages[]
				| select(.name == "lltop")
				| .dependencies[]
				| select(.name == "landlock-observability")
				| .req
			] == ["^0.0.0"])
		)
	'
