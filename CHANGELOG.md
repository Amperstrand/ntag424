# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.0-beta1] - 2026-04-26

Initial beta release of the `ntag424` crate — a transport-agnostic, `no_std`-compatible
Rust library for communicating with NXP NTAG 424 DNA NFC tags.

### What's included

**Authentication and session management** — AES-128 EV2 and NXP LRP authentication
(`AuthenticateEV2First` / `AuthenticateEV2NonFirst`). Session state is tracked through
the type system (`Session<Unauthenticated>` / `Session<Authenticated<_>>`), so a failed
command cannot leave the session in an inconsistent state.

**Tag commands** — `GetVersion`, `GetCardUID`, `ReadData` / `WriteData`,
`ISOReadBinary` / `ISOUpdateBinary`, `GetFileSettings` / `ChangeFileSettings`,
`GetFileCounters`, `GetKeyVersion`, `ChangeKey`, `SetConfiguration`, `ReadSignature`
(originality check via P-224 ECDSA), and tag tamper status readout.

**Secure Dynamic Messaging (SDM)** (`sdm` feature) — server-side PICC data decryption,
session key derivation, and MAC verification via `sdm::Verifier`. The `sdm_url_config!`
macro builds a ready-to-write NDEF byte string and matching `Sdm` settings from a URL
template at compile time.

**Key diversification** (`key_diversification` feature) — per-tag AES-128 key derivation
from a backend master key following NXP AN10922 §2.2.

**`serde` support** (`serde` feature) — `Serialize` / `Deserialize` on public types.

**`no_std` with optional `alloc`** — all core protocol logic is heap-free; the `alloc`
feature gates `Vec`-returning convenience wrappers.

Integration tests use a mock transport driven by NXP test vectors and recordings from
real hardware tags.
