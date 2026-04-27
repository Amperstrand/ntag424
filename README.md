[![Crates.io Version](https://img.shields.io/crates/v/ntag424?style=flat-square)](https://crates.io/crates/ntag424)
[![docs.rs](https://img.shields.io/docsrs/ntag424?style=flat-square)](https://docs.rs/ntag424)

# ntag424 Communication Protocol Library

A transport-agnostic Rust crate for communicating with
[NTAG 424 DNA](https://www.nxp.com/products/NTAG424DNA) NFC tags.

The crate is `no_std` compatible (with optional `alloc`) and
targets both embedded readers and host-side provisioning and verification.

## Features

- **Full application protocol**: Authentication (AES and LRP), file read/write,
  file settings, key changes, configuration, originality verification.
- **Secure Dynamic Messaging (SDM)** server-side verification, plus a
  `sdm_url_config!` macro for convenient config generation at compile time.
- **Key diversification** for deriving per-tag keys from a backend
  master key.
- **Transport-agnostic**: Bring your own NFC reader by implementing the
  `Transport` trait. The crate ships no transport itself.
- **`no_std`** with optional `alloc`. Designed so the linker can drop unused
  features under LTO.

## Usage

```sh
cargo add ntag424
```

See [docs.rs/ntag424](https://docs.rs/ntag424) for the full API documentation.

## Examples

`examples/provision/` is a complete, runnable provisioning tool built on
PC/SC. It covers reader selection, originality verification, optional LRP
mode and tag-tamper setup, per-tag key derivation and replacement, SDM URL
configuration, and NDEF file setup. Run it with:

```sh
cd examples
cargo run --bin ntag424-provision
```

## What is NTAG 424 DNA?

It's an NFC chip that can generate cryptographically signed or encrypted
identifiers on the fly, readable by standard NFC readers.
A standard phone tap on a tag with template

```
https://example.com/?p={picc}&m={mac}
```

returns something like

```
https://example.com/?p=EF963FF7828658A599F3041510671E88&m=94EED9EE65337086
```

A backend that knows the application keys can decrypt `p=`, recover the UID
and read counter, re-derive the session MAC key, and verify `m=`, giving
authenticated, replay-resistant tag identification using off-the-shelf NFC
readers.

## Testing

The crate has no hardware dependency for its tests: integration tests use a
mock transport that simulates tag responses, derived from NXP test vectors and
recordings collected from physical tags. Unit tests use the same sources.

## CI

CI is used for

- test suite runs,
- code formatting and linting, and
- release management.

## Sources

- [NTAG 424 DNA datasheet (NT4H2421Gx)](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
- [AN12196 — NTAG 424 DNA features and hints](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
- [AN12321 — NTAG 424 DNA features and hints (LRP mode)](https://www.nxp.com/docs/en/application-note/AN12321.pdf)
- [AN10922 — Symmetric key diversifications](https://www.nxp.com/docs/en/application-note/AN10922.pdf)
- Tests on real hardware tags.

_No tags were harmed during development of this crate._

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
