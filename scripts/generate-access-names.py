#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate Rust access-name tables from Linux Landlock headers.

Cross-check UAPI bits against kernel name lists so additions cannot be
silently omitted or mislabeled.
"""

import argparse
import difflib
import re
import sys
from pathlib import Path

CATEGORIES = (
    ("filesystem", "LANDLOCK_ACCESS_FS_", "_LANDLOCK_ACCESS_FS_NAMES", "FILESYSTEM_ACCESS_NAMES"),
    ("network", "LANDLOCK_ACCESS_NET_", "_LANDLOCK_ACCESS_NET_NAMES", "NETWORK_ACCESS_NAMES"),
    ("scope", "LANDLOCK_SCOPE_", "_LANDLOCK_SCOPE_NAMES", "SCOPE_NAMES"),
)
DEFINE_RE = re.compile(r"^\s*#\s*define\s+(\w+)\s+(.*?)\s*$")
BIT_RE = re.compile(r"^\(\s*1ULL\s*<<\s*([0-9]+)\s*\)$")
ENTRY_RE = re.compile(
    r'_LANDLOCK_NAME_ENTRY\s*\(\s*([A-Z][A-Z0-9_]*)\s*,\s*"([^"]*)"\s*\)'
)


def logical_lines(text):
    """Join C preprocessor backslash continuations."""
    result = []
    pending = ""
    for line in text.splitlines():
        if re.search(r"\\[ \t]+$", line):
            raise ValueError("whitespace follows a continuation backslash")
        continued = line.endswith("\\")
        piece = line[:-1] if continued else line
        pending += (" " if pending else "") + piece
        if not continued:
            result.append(pending)
            pending = ""
    if pending:
        raise ValueError("header ends with an unterminated backslash continuation")
    return result


def read_header(path):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error


def parse_uapi(path):
    constants = {category: {} for category, *_ in CATEGORIES}
    for line in logical_lines(read_header(path)):
        match = DEFINE_RE.match(line)
        if not match:
            continue
        macro, expression = match.groups()
        selected = next(
            ((category, prefix) for category, prefix, _, _ in CATEGORIES if macro.startswith(prefix)),
            None,
        )
        if selected is None:
            if macro.startswith("LANDLOCK_ACCESS_"):
                raise ValueError(f"unrecognized Landlock access category: {macro}")
            continue
        category, _ = selected
        bit_match = BIT_RE.match(expression)
        if not bit_match:
            raise ValueError(f"malformed single-bit expression for {macro}: {expression}")
        shift = int(bit_match.group(1))
        if shift >= 32:
            raise ValueError(f"bit for {macro} does not fit in u32: {shift}")
        if macro in constants[category]:
            raise ValueError(f"duplicate UAPI constant: {macro}")
        for other_macro, other_shift in constants[category].items():
            if shift == other_shift:
                raise ValueError(
                    f"duplicate {category} bit {shift}: {other_macro} and {macro}"
                )
        constants[category][macro] = shift
    for category, _, _, _ in CATEGORIES:
        if not constants[category]:
            raise ValueError(f"no {category} UAPI constants found")
    return constants


def parse_lists(path, constants):
    definitions = {}
    list_macros = {list_macro for _, _, list_macro, _ in CATEGORIES}
    for line in logical_lines(read_header(path)):
        match = DEFINE_RE.match(line)
        if not match or match.group(1) not in list_macros:
            continue
        macro, body = match.groups()
        if macro in definitions:
            raise ValueError(f"duplicate name-list definition: {macro}")
        definitions[macro] = body

    tables = {}
    for category, _, list_macro, _ in CATEGORIES:
        if list_macro not in definitions:
            raise ValueError(f"missing name list: {list_macro}")
        body = definitions[list_macro]
        entries = ENTRY_RE.findall(body)
        residual = ENTRY_RE.sub("", body)
        if residual.strip(" \t,"):
            raise ValueError(f"malformed entry in {list_macro}: {residual.strip()}")
        listed = {}
        names = set()
        for macro, name in entries:
            if macro in listed:
                raise ValueError(f"duplicate list entry in {list_macro}: {macro}")
            if name in names:
                raise ValueError(f'duplicate display name in {list_macro}: "{name}"')
            if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
                raise ValueError(f'invalid unprefixed name in {list_macro}: "{name}"')
            listed[macro] = name
            names.add(name)
        defined = set(constants[category])
        present = set(listed)
        missing = sorted(defined - present)
        extra = sorted(present - defined)
        if missing:
            raise ValueError(f"UAPI constants missing from {list_macro}: {', '.join(missing)}")
        if extra:
            raise ValueError(f"entries without matching UAPI constants in {list_macro}: {', '.join(extra)}")
        tables[category] = sorted(
            ((constants[category][macro], name) for macro, name in listed.items()),
            key=lambda entry: entry[0],
        )
    return tables


def render(tables):
    lines = [
        "// SPDX-License-Identifier: MIT OR Apache-2.0",
        "",
        "// Generated by scripts/generate-access-names.py; do not edit.",
        "",
    ]
    for category, _, _, rust_name in CATEGORIES:
        lines.append("#[rustfmt::skip]")
        lines.append(f"pub(crate) const {rust_name}: &[(u32, &str)] = &[")
        for shift, name in tables[category]:
            lines.append(f'    (1_u32 << {shift}, "{name}"),')
        lines.extend(["];"] if category == CATEGORIES[-1][0] else ["];", ""])
    return "\n".join(lines) + "\n"


def generate(kernel_tree):
    uapi = kernel_tree / "include/uapi/linux/landlock.h"
    internal = kernel_tree / "include/linux/landlock.h"
    constants = parse_uapi(uapi)
    return render(parse_lists(internal, constants))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "output path relative to the current directory when explicitly supplied "
            "(default: src/event/access_names.rs relative to the repository root)"
        ),
    )
    parser.add_argument("--check", action="store_true", help="compare without rewriting")
    return parser, parser.parse_args()


def main():
    parser, args = parse_args()
    repository = Path(__file__).resolve().parent.parent
    output = args.output if args.output is not None else repository / "src/event/access_names.rs"
    try:
        generated = generate(args.kernel_tree)
        encoded = generated.encode("utf-8")
        if args.check:
            try:
                current = output.read_bytes()
            except OSError as error:
                raise ValueError(f"cannot read output {output}: {error}") from error
            if current != encoded:
                old_text = current.decode("utf-8", errors="replace").splitlines(keepends=True)
                diff = difflib.unified_diff(
                    old_text,
                    generated.splitlines(keepends=True),
                    fromfile=str(output),
                    tofile=f"{output} (generated)",
                )
                sys.stderr.write("".join(diff))
                return 1
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(encoded)
        return 0
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    sys.exit(main())
