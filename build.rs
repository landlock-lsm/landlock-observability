// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::error::Error;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SOURCE: &str = "src/bpf/landlock_observability.bpf.c";
const BPF_HEADERS: [&str; 2] = ["src/bpf/event.h", "src/bpf/vmlinux.h"];

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENDIAN");
    println!("cargo:rustc-check-cfg=cfg(docsrs_build)");
    println!("cargo:rerun-if-changed={BPF_SOURCE}");
    for header in BPF_HEADERS {
        println!("cargo:rerun-if-changed={header}");
    }

    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:rustc-cfg=docsrs_build");
        return Ok(());
    }

    let target_endian =
        env::var("CARGO_CFG_TARGET_ENDIAN").map_err(|_| "CARGO_CFG_TARGET_ENDIAN is not set")?;
    let target_endian_flag = match target_endian.as_str() {
        "little" => "-mlittle-endian",
        "big" => "-mbig-endian",
        value => return Err(format!("unknown CARGO_CFG_TARGET_ENDIAN value: {value}").into()),
    };
    let output_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    let object = output_dir.join("landlock_observability.bpf.o");
    SkeletonBuilder::new()
        .source(BPF_SOURCE)
        .obj(object)
        .clang_args(["-Wall", "-Wformat=2", "-Werror", target_endian_flag])
        .build()?;

    Ok(())
}
