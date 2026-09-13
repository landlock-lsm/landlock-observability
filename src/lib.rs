// SPDX-License-Identifier: MIT OR Apache-2.0

// Runtime code must not introduce non-allocation panics; test assertions are exempt.
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::dbg_macro,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::print_stderr,
        clippy::print_stdout,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used
    )
)]

//! Reusable observability for Landlock.
//!
//! # Memory use
//!
//! [`state::State`] currently has no capacity or eviction policy. It retains
//! reconstructed rulesets, domains, and rules, plus one enforcement event per
//! observed TID in each domain, until it is dropped. Memory can therefore grow
//! without a configured bound in a long-running process. Configurable retention
//! limits and eviction are planned but are not implemented yet; the bounded
//! collector queue and [`aggregate::DenialAggregator`] do not bound `State`.
//!
//! This crate requires Rust 1.88 or later.

#![warn(missing_docs)]

pub mod aggregate;
pub mod collector;
pub mod event;
pub mod privilege;
pub mod state;

mod wire;
