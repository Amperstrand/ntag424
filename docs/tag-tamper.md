# NTAG 424 DNA TT — Tag Tamper notes

This note summarizes the Tag Tamper details found in:

- `docs/NT4H2421Tx.pdf` (rev. 3.0), especially sections `8.2.4.5`, `9.3.5`, `10`, `11.5.1`, `11.7.1`, and `11.9.1`
- `docs/AN12196 - NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints.pdf` (rev. 2.0)
- `docs/AN12321 - NTAG 424 DNA (TagTamper) features and hints - LRP mode.pdf` (rev. 1.0)

It focuses on:

1. enabling Tag Tamper via `SetConfiguration`
2. mirroring Tag Tamper state in the NDEF file via `ChangeFileSettings`
3. retrieving live status via `GetTTStatus`
4. deciding whether a chip supports Tag Tamper at all

## Status model

The tag exposes two one-byte status values:

- `TTPermStatus`: permanent, latched status
- `TTCurrStatus`: current measured status

Supported values (`NT4H2421Tx` §10.2, §11.9.1):

| Value | Meaning | Encoding |
|---|---|---|
| `43h` | Close | ASCII `'C'` |
| `4Fh` | Open | ASCII `'O'` |
| `49h` | Invalid | ASCII `'I'` |

Important behavior:

- Tag Tamper is **disabled at delivery**.
- Once enabled, the feature is **permanent** and cannot be disabled again.
- After enabling, measurements start from the **next activation** onward.
- While `TTPermStatus = Close`, a boot-time measurement is done after full ISO/IEC 14443-4 activation and during processing of the first command.
- If an open loop is detected, `TTPermStatus` is updated to `Open` and never returns to `Close`.
- `GetTTStatus` also triggers a measurement when the feature is enabled.
- `ReadData` / `ISOReadBinary` can also trigger a measurement when Tag Tamper mirroring is needed for SDM.

## Detecting Tag Tamper support

The reader can distinguish plain NTAG 424 DNA from NTAG 424 DNA TT by issuing
`GetVersion` and checking the **hardware subtype** byte from Part 1.

From the two datasheets' `GetVersion` Part 1 tables:

| Product | `HWSubType` meaning |
|---|---|
| `NT4H2421Gx` | `X2h` = `50 pF` |
| `NT4H2421Tx` | `X8h` = `50 pF + Tag Tamper` |

So the practical test is:

- upper nibble `0x2?` / datasheet notation `X2h` => **no Tag Tamper support**
- upper nibble `0x8?` / datasheet notation `X8h` => **Tag Tamper-capable silicon**

The low nibble still encodes the back-modulation variant:

- `0Xh` = strong back modulation
- `8Xh` = standard back modulation

So a reader should treat `HWSubType` as a bit of mixed information:

- one part says whether the IC is TT-capable
- one part says which back-modulation variant it uses

### Supported vs enabled

This only tells you whether the chip **supports** Tag Tamper.

On a TT-capable chip, the feature may still be disabled. To distinguish those
states:

1. call `GetVersion`
2. if `HWSubType` indicates TT support, call `GetTTStatus`
3. interpret the result:
   - `49h` / `'I'` => TT-capable, but feature not enabled yet
   - `43h` / `'C'` or `4Fh` / `'O'` => feature enabled and measured

### Current codebase mapping

In this repository, the reader-side hook for this decision is already exposed by
`ntag424-core/src/types/version.rs`.

The relevant accessor is:

- `Version::hw_sub_type()` (`version.rs:23-25`)

That means the natural implementation strategy is:

1. obtain a `Version` with `Session::get_version()`
2. inspect `version.hw_sub_type()`
3. classify the chip as TT-capable or not from that byte

`version.rs` currently exposes the raw byte only, so the Tag Tamper detection
logic still lives at the call site; there is no dedicated helper yet for
"is this a Tag Tamper chip?".

## `SetConfiguration`: enabling Tag Tamper

`SetConfiguration` is command `INS = 5Ch` and requires:

- authentication with `AppMasterKey`
- `CommMode.Full`
- application selected, not PICC level

The Tag Tamper-specific configuration is `Option = 07h` (`NT4H2421Tx` §11.5.1).

### Option `07h` payload

`Option 07h` carries **2 data bytes**:

| Field | Size | Meaning |
|---|---:|---|
| `TTConfig` | 1 byte | `bit0 = 1` enables Tag Tamper; `bit0 = 0` means no change; bits `7..1` RFU |
| `TTStatusKey` | 1 byte | access policy for `GetTTStatus` |

`TTStatusKey` values:

| Value | Meaning |
|---|---|
| `00h..04h` | require authentication with that AppKey for `GetTTStatus` |
| `0Eh` | free access to `GetTTStatus` (**default**) |
| `0Fh` | no access to `GetTTStatus` |

Other useful constraints from `NT4H2421Tx` §11.5.1:

- `Option 07h` must have data length `2`, otherwise `917E` / `LENGTH_ERROR`
- targeting a non-existing key yields `919E` / `PARAMETER_ERROR`
- no active `AppMasterKey` authentication yields `91AE` / `AUTHENTICATION_ERROR`
- issuing it at PICC level yields `919D` / `PERMISSION_DENIED`

### What the plaintext command data looks like

The `Option` byte is sent in the clear; the data bytes are wrapped in secure messaging.

For Tag Tamper, the logical command-specific payload is:

```text
Option = 07h
Data   = TTConfig || TTStatusKey
```

So the minimal plaintext parameter tuple to enable Tag Tamper with free `GetTTStatus` access is:

```text
07 01 0E
```

That is **not** a published on-wire APDU vector; the final C-APDU depends on the session keys, TI, command counter, encryption, and MAC.

### Current codebase mapping

In this repository, this `SetConfiguration` support belongs in
`ntag424-core/src/types/configuration.rs`.

The current implementation surface is the `Configuration` builder and its
`build()` wire-order emitter. Right now it models options `00h`, `04h`, `05h`,
`0Ah`, and `0Bh`, but **not** Tag Tamper `Option 07h`
(`Configuration` fields/build table in `configuration.rs:11-17`,
`configuration.rs:124-137`).

So implementing Tag Tamper configuration there would mean adding:

- a new stored payload for `Option 07h`
- a public builder API for `TTConfig` / `TTStatusKey`
- inclusion of `(0x07, payload)` in `Configuration::build()`

## File settings / SDM options for Tag Tamper mirroring

Tag Tamper mirroring is configured through `ChangeFileSettings` (`INS = 5Fh`) on the **NDEF file** (`FileNo 02h`), since SDM is only supported there (`NT4H2421Tx` §8.2.3.1, §11.7.1).

### Required fields

`ChangeFileSettings` uses these fields for Tag Tamper mirroring:

| Field | Meaning |
|---|---|
| `FileOption.bit6` | must be `1` to enable SDM and mirroring |
| `SDMOptions.bit3` | enables `TTStatus` mirroring |
| `SDMOptions.bit0` | ASCII mode; `NT4H2421Tx` only supports ASCII mode here |
| `TTStatusOffset` | 3-byte LSB-first offset of the 2-byte Tag Tamper placeholder |

Related `SDMOptions` bits (`NT4H2421Tx` §11.7.1):

| Bit | Meaning |
|---:|---|
| `7` | UID mirroring |
| `6` | `SDMReadCtr` mirroring |
| `5` | `SDMReadCtrLimit` enabled |
| `4` | `SDMENCFileData` enabled |
| `3` | `TTStatus` mirroring enabled |
| `0` | encoding mode (`1 = ASCII`) |

### How `TTStatus` is mirrored

From `NT4H2421Tx` §9.3.5:

- `TTStatus` is the concatenation `TTPermStatus || TTCurrStatus`
- both bytes are mirrored together
- they can be mirrored **plain** or **encrypted**
- the two status bytes are already ASCII encoded, so **no extra ASCII encoding** is applied
- only a **2-byte placeholder** is needed

Offset/range rules:

| Field | Rule |
|---|---|
| `TTStatusOffset` | present only if `SDMOptions.bit3 = 1` |
| `TTStatusOffset` range | `0 .. FileSize - 2` |
| Overlap | must not overlap mirrored `PICCData` or `SDMMAC` |

### Plain vs encrypted mirroring

#### Plain mirroring

Plain mirroring only needs:

- `FileOption.bit6 = 1`
- `SDMOptions.bit3 = 1`
- `TTStatusOffset` set to the placeholder location

The mirrored bytes in the returned NDEF are directly:

```text
TTPermStatus || TTCurrStatus
```

Example returned values:

```text
43 43   ; "CC"  perm=Close, curr=Close
4F 4F   ; "OO"  perm=Open,  curr=Open
43 4F   ; "CO"  perm=Close, curr=Open
49 49   ; "II"  feature not enabled / invalid
```

#### Encrypted mirroring

For encrypted Tag Tamper mirroring, `TTStatus` is not encrypted separately. Instead, it is inserted into the plaintext area that becomes `SDMENCFileData` (`NT4H2421Tx` §9.3.5, §9.3.7):

- `SDMOptions.bit4 = 1` (`SDMENCFileData`)
- `TTStatusOffset` must point **inside** the plaintext placeholder covered by `SDMENCOffset` / `SDMENCLength`
- the static file bytes at that position are replaced by `TTPermStatus || TTCurrStatus` **before** encrypting the SDMENC region

So for encrypted mirroring:

1. reserve an `SDMENCFileData` placeholder
2. place a 2-byte Tag Tamper slot inside that plaintext region
3. set `TTStatusOffset` to that slot

Both status bytes are either plain together or encrypted together; there is no mixed mode.

### Current codebase mapping

In this repository, the `ChangeFileSettings` / `GetFileSettings` side belongs in
`ntag424-core/src/types/file_settings.rs`.

The relevant existing types are:

- `SdmSettings` for the `SDMOptions` flags (`file_settings.rs:361-387`)
- `SdmOffsets` for the variable offsets and lengths (`file_settings.rs:335-344`)
- `SdmSettingsBuilder` for constructing SDM layouts (`file_settings.rs:399-545`)
- `FileSettings::decode` / `FileSettings::encode_change` for parsing and
  serializing the wire payload (`file_settings.rs:606-760`)

The current model already covers:

- `SDMOptions.bit7` UID mirroring
- `SDMOptions.bit6` `SDMReadCtr` mirroring
- `SDMOptions.bit5` `SDMReadCtrLimit`
- `SDMOptions.bit4` `SDMENCFileData`
- `SDMOptions.bit0` ASCII mode

But it does **not** yet model the Tag Tamper-specific pieces from Table 69:

- `SDMOptions.bit3` (`TTStatus` enabled)
- `TTStatusOffset`

Concretely, implementing Tag Tamper mirroring there would require extending the
types layer with something like:

- a boolean on `SdmSettings` for `TTStatus` mirroring
- a `tt_status: Option<u32>` field on `SdmOffsets`
- builder support to place the 2-byte `TTStatus` placeholder
- decode/encode logic that consumes and emits `SDMOptions.bit3` and
  `TTStatusOffset` in the correct Table 69 order

At the moment, `file_settings.rs` only emits/parses the UID, read-counter,
encrypted-PICCData, MAC-input, encrypted-file-data, MAC, and read-counter-limit
fields, so Tag Tamper SDM mirroring is still a missing extension point.

### Mirroring behavior in authenticated vs non-authenticated reads

Tag Tamper mirroring follows the same SDM visibility rules as the other mirror types:

- mirroring is applied in **not authenticated** state
- if the file is read while authenticated, normal secure messaging applies to the static file data instead

The datasheet also states that Tag Tamper mirroring is applied in not-authenticated state even if the read is possible through free `Read` / `ReadWrite`, not only through `SDMFileRead`.

## `GetTTStatus`

`GetTTStatus` is command `INS = F7h` (`NT4H2421Tx` §11.9.1).

High-level properties:

- returns `TTPermStatus` and `TTCurrStatus`
- triggers a fresh measurement for `TTCurrStatus` once the feature is enabled
- if that measurement detects open, `TTPermStatus` is updated to `Open`
- uses **encrypted secure messaging** / `CommMode.Full`

### Command / response shape

From the command tables:

| Item | Value |
|---|---|
| CLA | `90h` |
| INS | `F7h` |
| P1 | `00h` |
| P2 | `00h` |
| Data parameters | none |
| Response data | `TTPermStatus || TTCurrStatus` |
| Success status | `9100h` |

Response byte meanings (`NT4H2421Tx` Table 85):

| Byte | Values |
|---|---|
| `TTPermStatus` | `43h` Close, `4Fh` Open, `49h` Invalid |
| `TTCurrStatus` | `43h` Close, `4Fh` Open, `49h` Invalid |

Access control (`NT4H2421Tx` Table 86):

- `TTStatusKey = 0Eh`: free access
- `TTStatusKey = 0Fh`: `919D` / `PERMISSION_DENIED`
- `TTStatusKey = 00h..04h`: matching authentication required, else `91AE` / `AUTHENTICATION_ERROR`

### Documentation inconsistency

`NT4H2421Tx` has a small inconsistency here:

- the APDU summary table and parameter table say `GetTTStatus` has **no command data parameters**
- the Figure 28 text rendering shows an `Lc` field of `01`

For implementation purposes, the command tables are the more reliable description: the command-specific payload is just `INS = F7h` plus the secure-messaging wrapper required by `CommMode.Full`.

### Current codebase mapping

`GetTTStatus` itself is **not** represented in either
`ntag424-core/src/types/configuration.rs` or
`ntag424-core/src/types/file_settings.rs`.

Those two files only cover:

- `SetConfiguration` payload construction
- `ChangeFileSettings` / `GetFileSettings` payload construction and decoding

So if `GetTTStatus` is added later, the natural split is:

- `configuration.rs`: only the `TTStatusKey` setup via `SetConfiguration Option 07h`
- `file_settings.rs`: only the NDEF mirroring pieces (`SDMOptions.bit3`,
  `TTStatusOffset`)
- command/response types elsewhere: the actual `GetTTStatus` APDU and decoding
  of `TTPermStatus || TTCurrStatus`

## Published vectors found in the docs

I did **not** find a published, complete **Tag Tamper-specific** secure-messaging vector for:

- `SetConfiguration` with `Option 07h`
- `ChangeFileSettings` with `TTStatus` mirroring enabled
- `GetTTStatus`

What the docs *do* publish is:

1. exact field definitions for the Tag Tamper options and statuses
2. complete `SetConfiguration` examples for other options, useful as framing references

### `SetConfiguration` vector: enable Random ID (AES secure messaging)

From `AN12196` §6.2 / Table 27:

```text
Cmd.SetConfiguration C-APDU
905C000019008EA0138A7AF6FC8E99DF2A3A305602C43A7A3C9228C3134A00
```

This is `SetConfiguration`, but **not** Tag Tamper-specific.

### `SetConfiguration` vector: enable LRP mode (LRP secure messaging)

From `AN12321` §5 / Table 3:

```text
SetConfiguration Option = 05
Plain Data              = 00000000020000000000
Cmd.SetConfiguration C-APDU
905C000019050041B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300
```

This is also **not** Tag Tamper-specific, but it confirms the on-wire framing for `SetConfiguration` under secure messaging.

## Practical implementation summary

If you want Tag Tamper in the NDEF URL flow:

1. enable the feature once with `SetConfiguration(Option 07h, TTConfig.bit0=1, TTStatusKey=...)`
2. configure file `02h` with `ChangeFileSettings`
3. set `FileOption.bit6 = 1`
4. set `SDMOptions.bit3 = 1`
5. assign a 2-byte placeholder and write its offset to `TTStatusOffset`
6. if the status must be confidential, also enable `SDMENCFileData` and place the 2-byte TT slot inside that plaintext region
7. use `GetTTStatus` when you need an authenticated, explicit readout of `TTPermStatus` and `TTCurrStatus`
