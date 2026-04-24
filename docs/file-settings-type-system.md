# `FileSettings` type system — proposal

This document proposes a redesign of the types backing the
`ChangeFileSettings` / `GetFileSettings` payloads in
`ntag424/src/types/file_settings.rs`. The goal is to push as much of
the wire format's validity rules into the Rust type system as is
reasonably possible, so that "make illegal states unrepresentable"
replaces the current mix of optional fields + a `validate_sdm_settings`
pass. Where an invariant is dependent on runtime values (e.g. "no two
mirrored regions overlap") we keep a single `try_new` checkpoint, but we
never rely on a post‑construction linter running at encode time.

Reference: NT4H2421Tx rev 3.0, §11.7.1, Tables 69 and 71 (pages 70–75).

## 1. Why the current design is messy

Short tour of the friction points:

- `SdmSettings` is a flat 5‑field struct in which *every* field is
  optional or "empty‑by‑default". Whether a field is semantically valid
  depends on the combined bits of `SDMOptions` and
  `SDMAccessRights`. All of these couplings are checked after the fact
  by `validate_sdm_settings`, which is called from both
  `SdmSettings::try_from_parts` and `encode_change`.
- `PlainPiccDataMirror` is a 3‑variant enum (`Uid`, `ReadCounter`,
  `UidAndReadCounter`) that manually enumerates the non‑empty subsets
  of `{UID, SDMReadCtr}`. The builder has to pattern‑match across the
  variants on every `mirror_plain_uid` / `mirror_plain_read_counter`
  call to preserve the other field — a classic "rebuild the variant on
  every mutation" smell.
- `SdmReadAccess::encrypted_file_data` is `Option<Range<u32>>`, but
  setting it via the builder before `enable_read_access` is impossible
  without a `pending_encrypted_file_data` side‑channel, because at that
  moment the `read_access` field is still `None`. The builder has a
  hidden "pending" slot for exactly one field.
- The invariants "`SDMCtrRet != F` requires ReadCtr mirrored",
  "`SDMReadCtrLimit` requires ReadCtr mirrored" and "SDMENCFileData
  requires both UID and ReadCtr mirrored" are all checked by string
  matching in a validation routine. They are also the most common
  classes of mistake callers make.
- `AccessCondition` and a second private `WirePiccDataAccess` enum
  redundantly model the same nibble encoding with slightly different
  sets of legal values, because not every slot in `SDMAccessRights`
  accepts the same subset.
- `MAX_CHANGE_FILE_SETTINGS_LEN`, `ValueTooLarge`, and the u24 check
  leak into the public API even though 24‑bit offsets are a property
  of *every* offset field in the payload.
- Decode and encode each run an independent "SDM block present"
  branch and duplicate the ordering logic; any future change has to
  be mirrored in two places.

## 2. Invariants catalog

Tables 69 and 71 contain two classes of invariants.

### 2.1 Structural invariants (can move to the type system)

| # | Invariant | Source |
|---|-----------|--------|
| S1 | `FileOption` bits 7 and 5..2 are RFU and fixed to 0. | T69 |
| S2 | `SDMOptions` bits 2..1 are RFU = 00; bit 0 is fixed to 1 (ASCII). | T69 |
| S3 | `SDMAccessRights` bits 7..4 are RFU = F. | T69 |
| S4 | `AccessRights` nibbles are one of `{0..4, E, F}`. | T6 / T69 |
| S5 | `SDMMetaRead` nibble has only three *kinds* of values: encrypted key `0..4`, plain `E`, none `F`. | T69 |
| S6 | `SDMFileRead` nibble has only two kinds: key `0..4`, none `F`. `E` is illegal. | T69 |
| S7 | `SDMCtrRet` nibble kinds: key `0..4`, free `E`, none `F`. | T69 |
| S8 | `UIDOffset` is present **iff** `SDMOptions[7] = 1` and `MetaRead = E`. | T69 |
| S9 | `SDMReadCtrOffset` is present **iff** `SDMOptions[6] = 1` and `MetaRead = E`. | T69 |
| S10 | `PICCDataOffset` is present **iff** `MetaRead ∈ 0..4`. | T69 |
| S11 | `TTStatusOffset` is present **iff** `SDMOptions[3] = 1`. | T69 |
| S12 | `SDMMACInputOffset` and `SDMMACOffset` are present **iff** `FileRead ≠ F`. | T69 |
| S13 | `SDMENCOffset` and `SDMENCLength` are present **iff** `FileRead ≠ F` **and** `SDMOptions[4] = 1`. | T69 |
| S14 | `SDMReadCtrLimit` is present **iff** `SDMOptions[5] = 1`. | T69 |
| S15 | `MetaRead = F` iff `SDMOptions[7] = SDMOptions[6] = 0` (no PICC data mirrored of any kind). | T71 |
| S16 | `MetaRead = E` requires at least one of `SDMOptions[7]`, `SDMOptions[6]` set. | T71 |
| S17 | `SDMOptions[4] = 1` (ENC file data) requires `FileRead ≠ F` and both `SDMOptions[7] = SDMOptions[6] = 1`. | T71 |
| S18 | `SDMOptions[5] = 1` (read‑ctr limit) requires `SDMOptions[6] = 1`. | T71 |
| S19 | `SDMCtrRet ≠ F` requires `SDMOptions[6] = 1`. | T71 |
| S20 | SDM is only legal for FileNo `02h` (NDEF). | T71 |
| S21 | `SDMENCLength` is a multiple of 32. | T69 |
| S22 | `FileType` and `FileSize` are returned by `GetFileSettings` but **must not** be encoded by `ChangeFileSettings`. | T69 |

All of S1–S22 can be encoded in types: each is a static fact about the
shape of the payload or about which subset of fields coexist.

### 2.2 Numeric invariants (stay as `try_new` checks)

These require concrete offset values, so they cannot be expressed
without dependent types:

- N1. Every offset fits in 24 bits (`< 0x0100_0000`). → newtype with
  `::new` constructor.
- N2. `SDMMACInputOffset ≤ SDMMACOffset`.
- N3. `SDMENCOffset ≥ SDMMACInputOffset`, `SDMENCOffset + SDMENCLength ≤ SDMMACOffset`.
- N4. `SDMENCLength % 32 == 0` and `≥ 32`. (A length newtype covers the
  "multiple of 32" part statically; the upper bound depends on offsets.)
- N5. Offset pairs do not overlap (`SDMMAC` vs `UID`, `SDMReadCtr`,
  `PICCData`, `TTStatus`; `SDMENC` vs the same; `TTStatus` vs the
  three mirror regions; `UID` vs `SDMReadCtr`; …). Enumerated in Table 71.
- N6. If `TTStatusOffset` is inside `SDMENCFileData`, it must be fully
  inside the plaintext half (`TTStatusOffset + 2 ≤ SDMENCOffset + SDMENCLength/2`).
- N7. All offsets are `< FileSize − <region‑length>` for their region
  length. Not enforceable here because `FileSize` is not known at
  change time — the PICC enforces it.

## 3. Redesign

The backbone is three ideas:

1. **One enum per multi‑way nibble**, with variants that *carry the
   fields that each nibble value implies to exist*. The access‑rights
   word and the SDM‑options byte are then fully derived from the
   variant inhabited — no flag bookkeeping, no `validate_*` function.
2. **A private `Offset` newtype** (24‑bit) so the "`ValueTooLarge`"
   error vanishes from every user‑facing path. Same for
   `EncLength` (multiple of 32).
3. **`FileSettings` splits into two views**: `FileSettingsView`
   (read‑only, decoded from `GetFileSettings`) and `FileSettingsPatch`
   (what `ChangeFileSettings` accepts — no `FileType`/`FileSize`).
   This eliminates the "`FileSize` is ignored on encode" footgun.

### 3.1 Core building blocks

```rust
/// 24‑bit little‑endian offset used by every mirrorable field.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Offset(u32);

impl Offset {
    pub const MAX: u32 = 0x00FF_FFFF;
    pub const fn new(v: u32) -> Result<Self, FileSettingsError>;
    pub const fn get(self) -> u32;
}

/// SDMENCLength. Multiple of 32, ≥ 32. Upper bound is checked at `Sdm::try_new`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EncLength(u32);

impl EncLength {
    pub const fn new(v: u32) -> Result<Self, FileSettingsError>;
    pub const fn get(self) -> u32;
}
```

### 3.2 Access rights

Two different access‑right words (file AR and SDM AR) currently
share one nibble type. They don't actually have the same legal values,
so we give them distinct types:

```rust
/// Nibbles allowed in `AccessRights` (§8.2.3.3, Table 6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Access {
    Key(KeyNumber),   // 0h..4h
    Free,             // Eh
    NoAccess,         // Fh
}

pub struct AccessRights {
    pub read: Access,
    pub write: Access,
    pub read_write: Access,
    pub change: Access,
}

/// SDMFileRead nibble — only 0h..4h or Fh (no `Eh = Free` allowed).
/// Mapping this value onto an `Option<KeyNumber>` loses the fact that
/// the read key, when present, is necessarily a valid `KeyNumber`, so
/// we keep a dedicated type.
pub enum FileReadKey { Key(KeyNumber) }
```

We never name "SDMMetaRead" or "SDMCtrRet" as their own types — they
are implied by the `PiccData` / `ReadCtrFeatures` variants below.

### 3.3 The central enum: `PiccData` (replaces `PiccDataMirror`)

```rust
/// Whether and how PICCData is mirrored into the file.
///
/// The variant determines:
/// - `SDMMetaRead` nibble         (S5, S10, S15, S16)
/// - `SDMOptions[7]` (UID bit)    (S8, S15)
/// - `SDMOptions[6]` (RCtr bit)   (S9, S15)
/// - whether SDMReadCtr features live here at all  (S18, S19)
pub enum PiccData {
    /// MetaRead = F; SDMOptions[7] = SDMOptions[6] = 0.
    /// No UID, no SDMReadCtr, no PICCData in the URL.
    None,

    /// MetaRead = E; at least one nested field is `Some`.
    /// Exactly one variant per non‑empty subset of {UID, RCtr}.
    Plain(PlainMirror),

    /// MetaRead ∈ 0..4; a single encrypted PICCData blob carries
    /// whichever of UID/RCtr are selected by `content`.
    Encrypted {
        key: KeyNumber,
        offset: Offset,
        content: EncryptedContent,
    },
}

pub enum PlainMirror {
    Uid    { uid: Offset },
    RCtr   { read_ctr: ReadCtrMirror },
    Both   { uid: Offset, read_ctr: ReadCtrMirror },
}

/// `SDMReadCtr` mirror in plain mode: the offset *plus* the features
/// (limit, CtrRet) that are only meaningful when RCtr is mirrored.
pub struct ReadCtrMirror {
    pub offset: Offset,
    pub features: ReadCtrFeatures,
}

/// The two RCtr-gated features (S18, S19). Present *only* inside the
/// variants that include RCtr, making S18/S19 trivially satisfied.
pub struct ReadCtrFeatures {
    pub limit: Option<u32>,          // S14 / N (value range unconstrained)
    pub ret_access: CtrRetAccess,    // S7; `NoAccess` by default
}

pub enum CtrRetAccess { Key(KeyNumber), Free, NoAccess }

pub enum EncryptedContent {
    Uid,
    RCtr(ReadCtrFeatures),
    Both(ReadCtrFeatures),
}
```

Notes on how the SDM options byte becomes derivable:

- `SDMOptions[7]` = "the variant has a UID offset or encrypted content
  includes UID".
- `SDMOptions[6]` = "the variant has a `ReadCtrMirror`
  / `ReadCtrFeatures`".
- `SDMOptions[5]` = `features.limit.is_some()`.
- S18 and S19 are automatic: `ReadCtrFeatures` only exists on variants
  that mirror RCtr. A caller *cannot* construct a `limit` without first
  producing a `ReadCtrMirror` / `EncryptedContent::{RCtr,Both}`.

### 3.4 File read (SDMMAC / SDMENC)

```rust
/// SDMMAC window. The MAC is computed over `[input .. mac)`; the
/// degenerate case `input == mac` (empty MAC input) is allowed by the
/// spec and is the only way two `Offset`s can be equal here.
pub struct MacWindow {
    pub input: Offset,
    pub mac:   Offset,          // N2: mac >= input, checked in try_new
}

/// An SDMENCFileData range. The `length` carries the "multiple of 32"
/// invariant statically; the "inside the MAC window" check is N3.
pub struct EncFileData {
    pub start: Offset,
    pub length: EncLength,
}

/// Presence of this value means SDMFileRead ∈ 0..4 (S6, S12).
/// The two variants encode SDMOptions[4] directly (S13).
pub enum FileRead {
    MacOnly { key: FileReadKey, window: MacWindow },
    MacAndEnc {
        key: FileReadKey,
        window: MacWindow,
        enc: EncFileData,
    },
}
```

### 3.5 The top‑level SDM value

```rust
pub struct Sdm {
    picc_data: PiccData,
    file_read: Option<FileRead>,
    tamper_status: Option<Offset>,     // SDMOptions[3]; S11
    _private: (),                      // force use of constructors
}

impl Sdm {
    /// All cross-field numeric invariants (N2, N3, N5, N6) are checked
    /// here. Structural invariants have already been taken care of by
    /// the types of the arguments.
    pub fn try_new(
        picc_data: PiccData,
        file_read: Option<FileRead>,
        tamper_status: Option<Offset>,
    ) -> Result<Self, FileSettingsError>;

    /// Enforces S17: enc file data requires both UID and RCtr mirrored.
    /// Enforceable *statically* via a sealed constructor on `FileRead`
    /// that takes `&PiccData` and returns `Result<FileRead, _>`, i.e.
    /// `FileRead::mac_and_enc(&picc_data, ...)`. See §3.7.
    //
    // (accessors elided)
}
```

S17 is the only remaining structural invariant that links `PiccData`
and `FileRead`. We make it checked by construction by offering
`FileRead::mac_and_enc` only through a function that takes a
`&PiccData` and refuses anything but `PiccData::Plain(Both{..})` or
`PiccData::Encrypted{content: Both(..), ..}`. See §3.7 for the exact
API shape.

### 3.6 `FileSettings` split

```rust
/// Decoded `GetFileSettings` response (read‑only view).
pub struct FileSettingsView {
    pub file_type: FileType,
    pub file_size: u32,
    pub comm_mode: CommMode,
    pub access_rights: AccessRights,
    pub sdm: Option<Sdm>,
}

/// Payload for `ChangeFileSettings` (no `FileType`, no `FileSize`).
pub struct FileSettingsPatch {
    pub comm_mode: CommMode,
    pub access_rights: AccessRights,
    pub sdm: Option<Sdm>,
}

impl FileSettingsView {
    pub fn decode(buf: &[u8]) -> Result<Self, FileSettingsError>;
    pub fn into_patch(self) -> FileSettingsPatch;   // drops file_type + file_size
}

impl FileSettingsPatch {
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, FileSettingsError>;
}
```

This removes S22 as a class of bug: the encoder never sees a
`file_type` or `file_size` to silently discard.

### 3.7 Constructor ergonomics (replacing `SdmSettingsBuilder`)

The current builder exists mostly to hide two awkward facts: "setting
an offset *and* enabling its flag at the same time" and "side‑channel
storage for `encrypted_file_data`". Both disappear in the new design,
because you can't write a variant without supplying its fields. So the
builder can go. In its place we offer:

- Constructors for the common patterns that are hard to type out
  verbatim:

  ```rust
  impl PiccData {
      pub fn plain_uid(uid: Offset) -> Self;
      pub fn plain_read_ctr(offset: Offset, features: ReadCtrFeatures) -> Self;
      pub fn plain_both(uid: Offset, rctr: Offset, features: ReadCtrFeatures) -> Self;
      pub fn encrypted(key: KeyNumber, offset: Offset, content: EncryptedContent) -> Self;
  }

  impl ReadCtrFeatures {
      pub const NONE: Self = Self { limit: None, ret_access: CtrRetAccess::NoAccess };
      pub const fn with_limit(mut self, v: u32) -> Self;
      pub const fn with_ctr_ret(mut self, a: CtrRetAccess) -> Self;
  }
  ```

- A `FileRead::mac_and_enc` constructor whose signature *cannot* be
  misused (S17):

  ```rust
  impl FileRead {
      pub fn mac_only(key: FileReadKey, window: MacWindow) -> Self;

      /// Fails with `FileSettingsError::EncRequiresBothMirrors` if
      /// `picc_data` does not mirror both UID and SDMReadCtr.
      pub fn mac_and_enc(
          picc_data: &PiccData,
          key: FileReadKey,
          window: MacWindow,
          enc: EncFileData,
      ) -> Result<Self, FileSettingsError>;
  }
  ```

  The alternative is a "has both" witness type (`PiccDataWithBoth`) the
  caller obtains by destructuring `PiccData`; that is strictly
  stronger but forces every caller to write the destructuring. The
  `try_*` form is kept because it reads better for the 95% case.

### 3.8 Decoder / encoder sketch

The encoder becomes a straight walk over the enums — each `match` arm
emits exactly the offsets whose presence Table 69 predicates on that
arm's flags:

```rust
match &self.sdm {
    None => {}
    Some(sdm) => {
        let sdm_options = sdm.sdm_options_byte();    // derived
        let sdm_ar      = sdm.sdm_access_rights();   // derived
        w.u8(sdm_options)?;
        w.array(&sdm_ar.to_le_bytes())?;

        // S8/S9/S10: UIDOffset, SDMReadCtrOffset, PICCDataOffset
        match &sdm.picc_data {
            PiccData::None => {}
            PiccData::Plain(PlainMirror::Uid { uid }) => w.off(*uid)?,
            PiccData::Plain(PlainMirror::RCtr { read_ctr }) => w.off(read_ctr.offset)?,
            PiccData::Plain(PlainMirror::Both { uid, read_ctr }) => {
                w.off(*uid)?;
                w.off(read_ctr.offset)?;
            }
            PiccData::Encrypted { offset, .. } => w.off(*offset)?,
        }
        if let Some(tt) = sdm.tamper_status { w.off(tt)?; }        // S11
        if let Some(fr) = &sdm.file_read {                          // S12 + S13
            w.off(fr.window().input)?;
            if let FileRead::MacAndEnc { enc, .. } = fr {
                w.off(enc.start)?;
                w.u24_le(enc.length.get())?;
            }
            w.off(fr.window().mac)?;
        }
        if let Some(limit) = sdm.read_ctr_limit() {                 // S14
            w.u24_le(limit)?;
        }
    }
}
```

The decoder runs the same branches in the same order; because each
branch consumes exactly the fields its flags announce, the "were these
bits consistent?" cross-check collapses into "did every byte get
consumed?" — which is already covered by `TrailingBytes`.

### 3.9 What can still go wrong at runtime

After this redesign the only things `Sdm::try_new` needs to check are
the numeric invariants N1–N6:

- N1 is absorbed by `Offset::new`.
- N2, N3 are cheap comparisons inside `try_new`.
- N5 is a fixed set of "`a + len_a ≤ b || b + len_b ≤ a`" checks,
  one per pair listed in Table 71. The region lengths (`UIDLength`,
  `SDMReadCtrLength`, `PICCDataLength`, `SDMMACLength`) are constants
  per `CryptoMode` (AES vs LRP); `try_new` takes the suite as a
  parameter to validate lengths that depend on it, or returns a
  `NotValidatedForSuite` sentinel so callers can re‑check when they
  know the suite.
- N6 is one comparison when both TTStatus and EncFileData are present.

No more `validate_sdm_settings` string table; no more "is this
`Option<T>` consistent with that `bool`?".

## 4. Before / after cheat sheet

Before (AN12196 §5.9, Table 18 step 7):

```rust
let sdm = SdmSettings::builder()
    .mirror_encrypted_picc_data(KeyNumber::Key2, 0x20, PiccDataContent::UidAndReadCounter)
    .enable_read_access(KeyNumber::Key1, 0x43, 0x43)
    .allow_counter_read(AccessCondition::Key(KeyNumber::Key1))
    .build()?;
```

After:

```rust
let sdm = Sdm::try_new(
    PiccData::Encrypted {
        key: KeyNumber::Key2,
        offset: Offset::new(0x20)?,
        content: EncryptedContent::Both(
            ReadCtrFeatures::NONE.with_ctr_ret(CtrRetAccess::Key(KeyNumber::Key1)),
        ),
    },
    Some(FileRead::MacOnly {
        key: FileReadKey::Key(KeyNumber::Key1),
        window: MacWindow {
            input: Offset::new(0x43)?,
            mac:   Offset::new(0x43)?,
        },
    }),
    None,
)?;
```

The extra verbosity in the happy path is real; the win is that
*wrong* calls no longer compile. Examples that used to type‑check and
fail in `build()` or `encode_change`:

- `allow_counter_read(Key(1))` without mirroring RCtr — now impossible:
  `ret_access` lives inside `ReadCtrFeatures`, which only exists on
  RCtr variants.
- `limit_read_ctr(..)` without mirroring RCtr — same as above.
- `mirror_enc_file_data(..)` without enabling read access — no more
  orphan field; `EncFileData` is nested inside `FileRead::MacAndEnc`.
- `mirror_enc_file_data(..)` without mirroring both UID and RCtr — must
  go through `FileRead::mac_and_enc(&picc_data, ...)`.
- Constructing `SdmSettings` with `file_size = 123` and being surprised
  it is dropped on encode — `FileSettingsPatch` simply has no such
  field.
- Constructing an `AccessCondition::Free` for `SDMFileRead` — rejected
  by the `FileReadKey` type (no `Free` variant), matching the spec's
  "`Eh` illegal for SDMFileRead".

## 5. Implementation notes

- Keep the wire `Offset` newtype private‑unsafe: expose
  `const fn new(u32)` returning `Result` and a `get` accessor so the
  rest of the crate doesn't need to re‑check the 24‑bit bound.
- `const` is valuable for test fixtures; every constructor in §3.7 can
  stay `const` because all validation is numeric and compiler‑visible.
- `SdmSettings::builder` can be kept as a thin deprecated wrapper
  during migration (one release), mapping old calls onto the new
  constructors and returning `FileSettingsError::InconsistentOffsets`
  from `build()` only for cross‑field numeric failures. The
  structural mistakes now fail to compile, so there is nothing to
  translate.
- `crypto/sdm.rs` currently matches on `PiccDataMirror::{None, Plain,
  Encrypted}`. It needs one extra arm split (`PlainMirror` has three
  variants instead of three `PlainPiccDataMirror` enum cases), but
  the branches are one‑to‑one; no logic changes.
- `sdm_url.rs` consumes the same view; no additional impact beyond
  the renamed imports.
- Decoder needs one extra lookup table for the RFU bits (S1, S2, S3)
  so that reserved bits that ever come back as `1` are surfaced as
  `FileSettingsError::ReservedBitSet`, rather than being silently
  normalised. The current decoder masks them out.

## 6. Error type

The new `FileSettingsError` has fewer string‑based variants:

```rust
pub enum FileSettingsError {
    BufferTooShort { needed: usize, have: usize },
    TrailingBytes(usize),
    UnknownFileType(u8),
    InvalidAccessNibble { slot: NibbleSlot, value: u8 },
    OffsetOutOfRange(u32),              // > 24 bits
    EncLengthInvalid(u32),              // not a multiple of 32 or zero
    MacInputAfterMac,                   // N2
    EncOutsideMacWindow,                // N3
    MirrorsOverlap(OverlapKind),        // N5, N6
    ReservedBitSet { byte: &'static str, mask: u8 },
}
```

`InconsistentOffsets(&'static str)` goes away entirely — every case it
used to cover is now either a type error or one of the concrete
variants above.

## 7. Summary

| Old | New | Invariants absorbed |
|-----|-----|---------------------|
| `SdmSettings` with five optional fields + runtime validator | `Sdm { picc_data, file_read, tamper_status }` + `try_new` | S15–S19 at the type level, N1 via `Offset` |
| `PiccDataMirror` + `PlainPiccDataMirror` + `EncryptedPiccDataMirror` | `PiccData` with `PlainMirror { Uid, RCtr, Both }` and `Encrypted { content: EncryptedContent }` | S8–S10, S15, S16 |
| `SdmReadAccess` with `encrypted_file_data: Option<Range<u32>>` | `FileRead::{MacOnly, MacAndEnc}` with fields by variant | S12, S13 |
| `allow_counter_read` / `limit_read_ctr` as top‑level SDM settings | `ReadCtrFeatures` nested inside RCtr‑bearing variants | S18, S19 |
| `FileSettings.file_size` ignored on encode | `FileSettingsPatch` vs `FileSettingsView` | S22 |
| `ValueTooLarge` surfacing at encode time | `Offset::new` at construction | N1 |
| Flat access‑condition enum used for three different nibble slots | `Access`, `FileReadKey`, `CtrRetAccess` — one per slot | S5–S7 |
| `validate_sdm_settings` string‑keyed error | `FileSettingsError` numeric / overlap variants | — |

The net effect is that writing `cargo check` is a stronger verifier
than the current `build()` + `encode_change` pipeline, and the
remaining `try_new` path has nothing to say about shape — only about
numbers.
