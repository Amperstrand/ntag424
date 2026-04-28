# Changelog

All notable changes to this project will be documented in this file.

## [v0.1.0-beta2] - 2026-04-28

### Added

- Store key number used for authentication
- Add convenience methods for file read/write
- Add pcsc transport implementation in new crate `ntag424-pcsc`
- Refactor authenticated session API
- Add getter for session crypto mode
- Add small utility methods for tag tamper status and UID types
- Add offset adjustment and data decryption to the verifier

### Changed

- Pass SDM settings by reference to Verifier::try_new

### Documentation

- Summarize changelog of first release
- Add badges to README.md
- Fix badge links in README.md
- Fix markdown link formatting in README.md
- Point out that the NDEF permissions should be changed
- Add provisioning example
- Restructure the provision example
- Refactor provision example utils into a separate crate
- Add verification example

### Fixed

- Fix codeberg release step and formatting
- Use constant-time equality for authentication checks
- Release task should restore all Cargo.toml on failure

## [v0.1.0-beta1] - 2026-04-26

### Added

- Initial ntag424-core crate with LRP implementation
- Add skeleton for session management and transport abstraction
- Implement ECDSA signature verification for NTAG 424 DNA
- Implement GetCardUID and GetVersion commands
- Implement AES and LRP cryptographic routines and trait
- Implement AuthenticateEV2First command for AES
- Add NDEF app selection to AuthenticateEV2First
- Add MAC communication mode support
- Implement authenticated originality check (ReadSignature)
- Implement GetCardUID authenticated command
- Implement ChangeKey authenticated command
- Implement AuthenticateEV2First for LRP mode
- Add Configuration type for tag settings
- Implement SetConfiguration authenticated command
- Add FileSettings type for NTAG 424 DNA file configuration
- Add builder for SdmSettings configuration
- Add NFC Capability Container (CC) type
- Implement ISOReadBinary command for file reading
- Implement ReadData authenticated command
- Implement GetFileSettings, GetFileCounters, and GetKeyVersion
- Implement AuthenticateEV2NonFirst for AES and LRP modes
- Implement ISOUpdateBinary and WriteData commands
- Implement ChangeFileSettings authenticated command
- Add key diversification module
- Add SecureDynamicMessageVerifier with AES and LRP support
- SDM verification with AES and LRP support
- Add serde support for SDM verifier behind a feature flag
- Capture PCD/PD capability bytes during authentication
- Add tag tamper detection support
- Add tag tamper extraction helper to SDM verifier
- Add SDM URL module for secure message URL handling
- Add sdm_url_config! macro for compile-time SDM URL provisioning
- Use better panic messages and patterns
- Add `Response::status()` accessor
- Add forbid(unsafe_code) to ntag424
- Make MSRV explicit

### Changed

- Rename ntag424core to ntag424-core
- Reorganize crypto module and switch to impl Future
- Parameterize Authenticated with SessionSuite
- Extract Version parsing and improve response code documentation
- Deduplicate test vectors and helpers
- Split key_number into MasterKey and NonMasterKey types
- Extract common response parsing functionality
- Require consuming session for authenticated commands
- Add get_uid method to Transport trait
- Split Session implementation into separate modules
- Reorganize SDM configuration for better usability
- Redesign file settings API with strongly-typed builders
- Split module into sub-modules
- Split module into sub-modules
- Reanme crate from `ntag424-core` to `ntag424`
- Re-export common types at the crate root
- Rename `SecureDynamicMessageVerifier` to `Verifier`
- Make `FileSettingsPatch` a builder struct
- Remove `FileReadKey` wrapper type and use `KeyNumber` directly
- Return fixed arrays from LRP generators

### Continuous Integration

- Add CI workflows for clippy, doc, fmt, and test
- Add no_std check to CI
- Add release workflow and just task

### Documentation

- Add comprehensive SDM documentation
- Clarify LRP mode configuration behavior
- Add high-level hardware description for NTAG 424 DNA
- Update doc comments with first-line summaries
- Update library documentation and remove technical implementation details
- Update hardware and configuration documentation
- Improve documentation clarity and add test notes
- Add binary size recommendations
- Replace NXP jargon with accessible terminology
- Add provisioning example
- Add configuration overview
- Add comprehensive crate API review
- Add NDEF content example and improve formatting
- Update crate review with resolved feedback
- Add README.md
- Mention section numbers, CC file features, and key number distinction
- Add some missing doc strings
- Add description of APDU response status words
- Add doc comments to `Version` struct getters
- Fix link and remove obsolete doc.rs attribute
- Fix backtick warning
- Clarify the contract of `Transport::get_uid` and `Session::<Authenticated>::get_uid`
- Add rationale for `Session<Authenticated>` method shapes
- Remove completed crate review document
- Clarify the behavior of the plain read/write helpers on authenticated sessions

### Fixed

- Correct bit mask for calendar year in version struct
- Correct rustdoc example in FileSettings
- Correct SetConfiguration response handling
- Improve GetFileCounters and fix file counter handling
- Correct alloc feature usage
- Add validation for encrypted file data settings
- Correct bugs in tamper detection after hardware testing
- Add expected field to UnexpectedLength errors
- Add license files
- Resolve some api asymmetries
- Update usage of old crate name
- Make `Sdm::try_new` check PICC overlap
- Use correct path for CryptoMode in documentation tests
- Use constant-time comparison for truncated MACs in secure channel response verification
- Rename `FileSettingsPatch` to `FileSettingsUpdate` and clarify docs
- Harden AES-CBC helper block handling
- Return typed errors for command input validation

### Maintenance

- Add dummy types module placeholder
- Add Justfile for development commands
- Update crate metadata for publication
- Remove test data files
- Steps towards REUSE license compliance
- Update cargo metadata
- Remove editor lock files from git
- Remove obsolete docs

### Other

- Normalize em-dashes to hyphens in comments

### Tests

- Add test cases using real hardware captures
- Add comprehensive tests using real hardware captures
- Add tag tamper tests using real hardware captures
