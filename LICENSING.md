# Licensing

## License

This crate is licensed under **MIT OR Apache-2.0**, inherited from the upstream
project [jannschu/ntag424](https://codeberg.org/jannschu/ntag424) on Codeberg.

## Fork relationship

This is a fork of jannschu/ntag424 maintained by Amperstrand for use by:
- [bolty-rs](https://github.com/Amperstrand/bolty-rs) — Bolt Card / NTAG424 DNA programmer
- [ccid-firmware-rs](https://github.com/Amperstrand/ccid-firmware-rs) — CCID smartcard reader firmware

## Branches

| Branch | Base | Description |
|---|---|---|
| `upstream-sync` | jannschu/ntag424 main | Tracks upstream, no changes |
| `feature/sdm-disabled` | upstream-sync | Adds `Sdm::disabled()` constructor for wipe operations |
| `fix/lencap` | feature/sdm-disabled | Fixes AuthenticateEV2First LenCap=0x03 for NTAG 424 DNA |
| **`ai-experiments`** (default) | fix/lencap | Integration branch with both patches |

## Patches

See GitHub issues for detailed documentation of each patch, including spec
references, A/B hardware test results, and upstream contribution plans.

## SPDX

`SPDX-License-Identifier: MIT OR Apache-2.0`
