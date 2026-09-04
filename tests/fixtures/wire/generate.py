#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Generate fixed wire-decoder fixtures independently of Rust layout code.

Use explicit offsets and both byte orders so decoding is not checked against
the same definitions that implement it.
"""

import argparse
import struct
from pathlib import Path

SIZE = 344


def record(kind: int, timestamp: int, byte_order: str) -> bytearray:
    data = bytearray(SIZE)
    struct.pack_into(f"{byte_order}Q", data, 0, timestamp)
    data[8] = kind
    return data


def u32(data: bytearray, offset: int, value: int, byte_order: str) -> None:
    struct.pack_into(f"{byte_order}I", data, offset, value)


def u64(data: bytearray, offset: int, value: int, byte_order: str) -> None:
    struct.pack_into(f"{byte_order}Q", data, offset, value)


def fixed(data: bytearray, offset: int, size: int, value: bytes) -> None:
    if len(value) != size:
        raise ValueError((offset, size, len(value)))
    data[offset : offset + size] = value


def denial(
    data: bytearray, seed: int, same_exec: int, logged: int, byte_order: str
) -> None:
    u64(data, 16, 0xD000000000000000 + seed, byte_order)
    u64(data, 24, 0 if seed == 5 else 0xA000000000000000 + seed, byte_order)
    u32(data, 32, 0x51000000 + seed, byte_order)
    creator_comm = (
        b"sixteen-byte-cmd"
        if seed == 9
        else f"creator-{seed}\0tail".encode().ljust(16, b"!")
    )
    fixed(data, 36, 16, creator_comm)
    u64(data, 56, 0xC100000000000000 + seed, byte_order)
    u32(data, 64, 0x80010000 + seed, byte_order)
    data[68] = same_exec
    data[69] = logged


def encoded_fixtures(byte_order: str, suffix: str) -> dict[str, bytes]:
    out = {}

    data = record(1, 0x1100000000000001, byte_order)
    u64(data, 16, 0xA100000000000001, byte_order); u32(data, 24, 0x12000001, byte_order)
    u32(data, 28, 0x80010005, byte_order); u32(data, 32, 0x8000000A, byte_order); u32(data, 36, 0x80000003, byte_order)
    out[f"01-ruleset-create-{suffix}.bin"] = bytes(data)

    data = record(2, 0x2200000000000002, byte_order)
    u64(data, 16, 0xA200000000000002, byte_order); u32(data, 24, 0x23000002, byte_order)
    u32(data, 28, 0x80004006, byte_order); u32(data, 32, 0x34000002, byte_order); u64(data, 40, 0x4500000000000002, byte_order)
    path = b"/fixture/\xff\x1b" + b"\0" + b"ignored-suffix"
    fixed(data, 48, 256, path.ljust(256, b"Z"))
    out[f"02-fs-rule-add-{suffix}.bin"] = bytes(data)

    data = record(3, 0x3300000000000003, byte_order)
    u64(data, 16, 0xA300000000000003, byte_order); u32(data, 24, 0x34000003, byte_order)
    u32(data, 28, 0x80000009, byte_order); u64(data, 32, 0x5600000000000003, byte_order)
    out[f"03-network-rule-add-{suffix}.bin"] = bytes(data)

    data = record(4, 0x4400000000000004, byte_order)
    u64(data, 16, 0xA400000000000004, byte_order); u32(data, 24, 0x45000004, byte_order)
    u64(data, 32, 0xD400000000000004, byte_order); u64(data, 40, 0, byte_order)
    u32(data, 48, 0x56000004, byte_order); fixed(data, 52, 16, b"sixteen-byte-cmd")
    out[f"04-domain-create-{suffix}.bin"] = bytes(data)

    data = record(5, 0x5500000000000005, byte_order); denial(data, 5, 1, 0, byte_order)
    u32(data, 72, 0x72000005, byte_order); u64(data, 80, 0x8300000000000005, byte_order)
    fixed(data, 88, 256, b"P" * 256)
    out[f"05-fs-denial-{suffix}.bin"] = bytes(data)

    data = record(6, 0x6600000000000006, byte_order); denial(data, 6, 0, 1, byte_order)
    u64(data, 72, 0x7400000000000006, byte_order); u64(data, 80, 0x8500000000000006, byte_order)
    out[f"06-network-denial-{suffix}.bin"] = bytes(data)

    data = record(7, 0x7700000000000007, byte_order); denial(data, 7, 1, 1, byte_order)
    u64(data, 72, 0, byte_order); u32(data, 80, 0x86000007, byte_order)
    fixed(data, 84, 16, b"ptrace-target\0xy")
    out[f"07-ptrace-denial-{suffix}.bin"] = bytes(data)

    data = record(8, 0x8800000000000008, byte_order); denial(data, 8, 0, 0, byte_order)
    u64(data, 72, 0xE800000000000008, byte_order); u32(data, 80, 0x97000008, byte_order)
    fixed(data, 84, 16, b"signal-target\0xy")
    out[f"08-signal-denial-{suffix}.bin"] = bytes(data)

    data = record(9, 0x9900000000000009, byte_order); denial(data, 9, 1, 0, byte_order)
    u64(data, 72, 0xE900000000000009, byte_order); u32(data, 80, 0xA8000009, byte_order)
    out[f"09-abstract-unix-denial-{suffix}.bin"] = bytes(data)

    data = record(10, 0xAA0000000000000A, byte_order)
    u64(data, 16, 0xDA0000000000000A, byte_order); u64(data, 24, 0xAB0000000000000A, byte_order)
    out[f"10-domain-free-{suffix}.bin"] = bytes(data)

    data = record(11, 0xBB0000000000000B, byte_order)
    u64(data, 16, 0xAB0000000000000B, byte_order); u32(data, 24, 0xBC00000B, byte_order)
    out[f"11-ruleset-free-{suffix}.bin"] = bytes(data)

    data = record(12, 0xCC0000000000000C, byte_order)
    u64(data, 16, 0xDC0000000000000C, byte_order); u32(data, 24, 0xCD00000C, byte_order)
    data[28] = 1; data[29] = 0; data[30] = 1
    out[f"12-domain-enforce-{suffix}.bin"] = bytes(data)

    return out


def fixtures() -> dict[str, bytes]:
    """Return both native-endian encodings of the same semantic records."""
    return {
        **encoded_fixtures("<", "little-endian"),
        **encoded_fixtures(">", "big-endian"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    expected = fixtures()
    actual_names = {path.name for path in directory.glob("*.bin")}
    if args.check:
        if actual_names != set(expected):
            return 1
        return 0 if all((directory / name).read_bytes() == value for name, value in expected.items()) else 1
    for name, value in expected.items():
        (directory / name).write_bytes(value)
    for name in actual_names - set(expected):
        (directory / name).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
