[![Crates.io Version](https://img.shields.io/crates/v/ntag424?style=flat-square)](https://crates.io/crates/ntag424)
[![docs.rs](https://img.shields.io/docsrs/ntag424?style=flat-square)](https://docs.rs/ntag424)

# ntag424 Communication Protocol Library

A transport-agnostic Rust crate for communicating with
[NTAG 424 DNA](https://www.nxp.com/products/NTAG424DNA) NFC tags.

The crate is `no_std` compatible (with optional `alloc`) and
targets both embedded readers and host-side provisioning and verification.

## Features

- **High- and low-level APIs**: Use the high-level API for opinionated flows like
  provisioning and SDM verification, or the low-level API for direct command
  control and custom flows.
- **Full application protocol**: Authentication (AES and LRP), file read/write,
  file settings, key changes, configuration, originality verification.
- **Comprehensive tests and documentation** using real tag data and
  official test vectors.
- **Secure Dynamic Messaging (SDM)** server-side verification, plus a
  `sdm_url_config!` macro for convenient config generation at compile time.
- **Key diversification** for deriving per-tag keys from a backend
  master key.
- **Transport-agnostic**: Bring your own NFC reader by implementing the
  `Transport` trait. The crate ships no transport itself.
- **`no_std`** with optional `alloc`.

## Usage

Provision a tag and verify SDM-signed reads using the high-level API:

```rust
use ntag424::high_level::{provision, ApplicationVerifier, VerifiedTagReadout};

// Provisioning a tag

let mut rng: SysRng = rand::make_rng();
let app_verifier: ApplicationVerifier = provision(
        // a `Transport` implementation
        &mut transport,
        "https://example.com/v1/?p={picc}&m={mac}",
        // securely stored master key for diversification
        &master_key,
        &mut rng,
    )
    .await?;
// store `app_verifier` for verification

// Verifying a tag read

let input = b"https://example.com/v1/?p=...&m=...";
let mut read_counter = 0u32;
let result = app_verifier.verify(&master_key, input, &mut read_counter).await;
match result {
    Ok(VerifiedTagReadout { uid, read_ctr, tamper_status }) => {
        // Tag verified successfully
    }
    Err(e) => {
        // Verification failed
    }
}
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

`examples/verification/` is a companion server-side verifier. It reads the
JSON output produced by the provision tool, then loops over tag taps —
decrypting PICC data, deriving the per-tag session key, and verifying the
SDM MAC. Run it with:

```sh
cd examples
cargo run --bin ntag424-verification
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

## Related work

- [barnettlynn/nfctools](https://github.com/barnettlynn/nfctools). A Go library and CLI tool.
- [nikeee/node-ntag424](https://github.com/nikeee/node-ntag424). A Node.js library.
- [luu176/NTAG424-SDM](https://github.com/luu176/NTAG424-SDM). A Python script.
- [Obsttube/MFRC522_NTAG424DNA](https://github.com/Obsttube/MFRC522_NTAG424DNA). A C++ library for Arduino.
- [BTCPayServer.NTag424](https://www.nuget.org/packages/BTCPayServer.NTag424). A .NET library.
- [johnnyb/ntag424-java](https://github.com/johnnyb/ntag424-java). A Java library.

## Usage of AI and LLMs

This project used generative AI tools for:

- Code and API design review
- Spec and data sheet research and review
- Documentation review and improvement
- Test case generation
- Precisely scoped code refactoring and implementation

All AI-generated content was reviewed and edited by a human before inclusion in the project.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
