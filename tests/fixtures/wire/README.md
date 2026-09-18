# Wire decoder fixtures

These files represent twelve logical 352-byte records that exercise every
private event-decoder variant. Each logical record is committed twice: the
`-little-endian.bin` file contains the native scalar representation of a
little-endian producer, and the `-big-endian.bin` file contains the equivalent
big-endian representation. Rust tests select the set matching `target_endian`,
so the production `from_ne_bytes` path is exercised correctly on either
architecture.

Their absolute offsets correspond to the private producer layout in
`src/bpf/event.h`, whose compiled static assertions independently verify every
field, padding region, payload size, and the complete record size.

`generate.py` is a maintenance-only independent semantic oracle. It uses one
set of literal values and absolute offsets, including access-mask bit 63, to
generate both byte orders with Python's standard packing support; it neither
imports nor parses the Rust decoder. Regenerate all 24 files with `./generate.py`, or validate their exact
names and contents with `./generate.py --check`. Cargo does not run this script.
