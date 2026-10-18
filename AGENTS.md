# AGENTS.md — ntag424 (fork of jannschu/ntag424)

**Line canon**: this repo is one node of the boltcard line. The canonical
doctrine — repo map, SUN read-path architecture, the vectors-as-oracle
conformance rule, bench touchpoints — lives in
[ntag424-vectors/AGENTS.md](https://github.com/Amperstrand/ntag424-vectors/blob/main/AGENTS.md).
The oracle rule in one line: **every implementation passes every
`vectors.json` vector its API can express, skips are counted aloud,
vendored copies must not drift**.

## Purpose

Transport-agnostic Rust crate for the NTAG 424 DNA command protocol —
authentication (AES/LRP), file read/write, and SDM (secure dynamic
messaging) configuration/verification. `no_std` compatible (optional
`alloc`) for embedded readers. This **fork** (issue #4) carries the
changes needed by bolty-rs (programmer) and ccid-firmware-rs (reader
firmware); both consumers are hardware-verified with real NTAG 424 DNA
cards. All changes are intended for upstream feedback — this is not a
divergent fork, it is a staging area.

## Branch structure (the fork contract)

| Branch | Base | Contents |
|---|---|---|
| `upstream-sync` | jannschu/ntag424 v0.1.1 | tracks upstream, zero changes |
| `feature/sdm-disabled` (#2) | upstream-sync | `Sdm::disabled()` (merged PR1) |
| `fix/lencap` (#3) | feature/sdm-disabled | LenCap=0x03 hardware fix |
| **`ai-experiments`** (default) | fix/lencap | integration branch, both patches |

Rebase discipline over merge commits: each feature branch must stay
individually upstream-submittable. Open PRs (5: AES auth fixtures for
LenCap=0x03; 6: docs correction) ride the integration branch.

## Build / test

```bash
cargo build
cargo test
cargo build --no-default-features   # no_std contract
```

The AES authenticate fixtures were regenerated for LenCap=0x03 (PR5) —
fixture changes here are hardware-behavior statements, not test churn:
AuthenticateEV2First against real NTAG 424 DNA expects LenCap=0x03 (issue
#3). Do not "fix" a failing auth fixture back to the old bytes without a
card on the bench.

## Rules for agents

- Crypto-visible changes (SDM construction, MAC inputs, key derivation)
  are conformance changes: check them against the canonical vectors
  (Amperstrand/ntag424-vectors) — anything the crate's API can express
  must pass, skips counted aloud.
- Hardware claims need hardware: a change justified by card behavior gets
  verified on a real NTAG 424 DNA card (via bolty-rs or the bench
  readers `ref-acr1252` / `ref-cardman`) before it reshapes the
  integration branch.
- No secrets in fixtures or docs; upstream-submittable means no
  Amperstrand-internal references in commit messages on the feature
  branches.
