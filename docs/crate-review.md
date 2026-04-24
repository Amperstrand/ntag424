# Review: `ntag424` API & documentation

Target audience: a generalist Rust developer who has never read NT4H2421Gx. The
goal is a high-quality, stable API. The crate is well thought out, well cited
against the spec, and its feature‑gating / `no_std` hygiene is solid. What
follows are concrete things worth fixing before a 1.0, ordered by impact for a
hands‑on user.

I validated the most critical findings by reading the source and running
`RUSTDOCFLAGS='-W rustdoc::all' cargo doc --all-features --no-deps`; only three
real rustdoc warnings are reported today (see §4.4).

---

## 1. Top‑level story works, with some gaps

`src/lib.rs` does a good job explaining _what_ the chip is and _why_ SDM
exists, and the "Provisioning example" is a strong on‑ramp. A few things a
beginner still has to reverse‑engineer:

- **Typestate isn't named.** `Session<Unauthenticated>` vs
  `Session<Authenticated<AesSuite | LrpSuite>>` is the central shape of the
  API, but the crate docs never spell it out. A short paragraph in `lib.rs`
  ("Authentication state is tracked in the type; authenticating consumes the
  session and returns one in the new state; most authenticated commands
  likewise consume `self` and hand it back on success — see §3 below") would
  prevent a lot of head‑scratching the first time `session.authenticate_aes(…)`
  returns something of a different type.

## 2. Re‑exports and naming

## 3. Method shape on `Session<Authenticated<_>>`

**Rationale (confirmed).** Most authenticated methods take `self` by value
and return `Self` on success because on any error the authentication is lost
— the secure channel's MAC counter or the PICC's view of the session can be
desynchronised, and continuing to use it would at best produce more errors
and at worst silently violate invariants. Dropping `self` on the error path
forces the caller to re‑authenticate, which is the correct behaviour. **This
is a good design decision and worth keeping**; it just needs to be documented
and applied consistently.

Audit of the current shape (`src/session/authenticated.rs`):

| Method                 | `self` | Returns                          | Crosses secure channel? |
| ---------------------- | :----: | -------------------------------- | :---------------------: |
| `get_version`          | owned  | `(Version, Self)`                |        yes (MAC)        |
| `get_uid`              | owned  | `([u8; 7], Self)`                |           yes           |
| `get_file_counters`    | owned  | `(u32, Self)`                    |           yes           |
| `get_file_settings`    | owned  | `(FileSettingsView, Self)`       |           yes           |
| `get_tt_status`        | owned  | `(TagTamperStatusReadout, Self)` |           yes           |
| `change_key`           | owned  | `Self`                           |           yes           |
| `change_master_key`    | owned  | `Session<Unauthenticated>`       |  yes (always de‑auths)  |
| `change_file_settings` | owned  | `Self`                           |           yes           |
| `set_configuration`    | owned  | `Self`                           |           yes           |
| `verify_originality`   | owned  | `Self`                           |           yes           |
| `enable_lrp`           | owned  | `Session<Unauthenticated>`       |  yes (always de‑auths)  |
| `read_file_with_mode`  | owned  | `(usize, Self)`                  |  only in `Mac`/`Full`   |
| `write_file_with_mode` | owned  | `Self`                           |  only in `Mac`/`Full`   |
| **`read_file_plain`**  | `&mut` | `usize`                          |           no            |
| **`write_file_plain`** | `&mut` | `()`                             |           no            |

`read_file_plain` and `write_file_plain` using `&mut self` is _consistent_ with
the rationale above: they dispatch `ReadData` / `WriteData` in plain
communication mode (`authenticated.rs:269‑343`) and never touch the MAC
counter through `SecureChannel`, so an error on the wire cannot desynchronise
the authenticated state — only the `CmdCtr` advances on success. A failed
plain read is safely retryable on the same session.

This is good, but two things should change:

1. **Document the invariant.** In the `Session<Authenticated>` docstring,
   state explicitly: _"Methods that cross the secure channel take `self` by
   value: any error desynchronises the channel with the PICC, so the session
   is consumed and the caller must re‑authenticate. Methods that only issue
   plain‑mode commands take `&mut self` and are safe to retry."_ Then the
   `&mut self` outliers stop looking like bugs.

2. **Fix the asymmetries that remain:** _(resolved)_

## 4. Documentation gaps & errors

### 4.1 TODOs in shipped public documentation

- `src/types/configuration.rs:39` and `:52` — `with_random_uid_enabled` and
  `with_chained_writing_disabled` both carry `// TODO: extend docs, briefly
explain the consequences`. Both toggle **permanent** chip behaviour; the
  docs must be complete before a user enables them.
- `src/types/version.rs:85‑86` — "TODO: clarify padding for random ID which
  are shorter".
- `src/types/version.rs:93` — "TODO: BE or LE int or what?" for
  `batch_number()`. The function returns `&[u8; 4]` with _no_ docstring, so a
  user has no idea what to do with those bytes.

### 4.2 Missing per‑item docs on public fields / variants

Hands‑on users lean heavily on rustdoc for struct fields. The following
public fields are undocumented:

- `src/types/uid.rs:10‑11` — `Uid::Fixed([u8; 7])`, `Uid::Random([u8; 4])`.
  The outer doc (`:1‑7`) says the random variant's leading byte is `0x08`
  per ISO/IEC 14443‑3 but doesn't tell the reader whether that `0x08` is
  included in the 4 bytes.
- `src/types/tt_status.rs:14` — `TagTamperStatus::Unknown(u8)` has no doc
  on what byte values can end up there.
- `src/types/version.rs:15‑46, 50‑76` — **every** `hw_*` / `sw_*` getter on
  `Version` is undocumented. Users have no idea what `hw_protocol_type()`
  returns or what to compare it against. At minimum link to
  "NT4H2421Gx §10.5.2, Table 58" next to each.

### 4.3 Real rustdoc warnings

Running `RUSTDOCFLAGS='-W rustdoc::all' cargo doc --all-features --no-deps`:

- `src/crypto/key_diversification.rs:1` — "documentation test in private
  item". The module is `pub` only under `#[cfg(feature =
"key_diversification")]` via `lib.rs:268‑331`, but the doctest lives in
  the inner module itself. Move the example up to the
  `pub mod key_diversification { … }` re‑export in `lib.rs`, or hoist it
  into the re‑exported items' own rustdoc.
- `src/types/file_settings.rs:994‑995` — two "unescaped backtick" warnings
  on the doc of `MAX_CHANGE_FILE_SETTINGS_LEN` (the formula spans two lines
  with stray backticks).

Note: an earlier exploration claimed "6 broken intra‑doc links". That was
**not reproducible**. The three warnings above are the full set on today's
tree.

### 4.4 `docs.rs` feature tags

- `lib.rs:264‑266` — `pub mod sdm` carries
  `#[cfg_attr(docsrs, doc(cfg(feature = "sdm")))]`. Good.
- `lib.rs:267` — `pub mod key_diversification` is `#[cfg(feature =
"key_diversification")]` but **missing** the `doc(cfg(...))` attribute.
  Users browsing docs.rs won't see a feature badge.
- The `alloc`‑gated items in `src/sdm_url.rs` (`:27`, `:89`, `:228`) and
  `src/crypto/sdm.rs` (`:21`, `:92`, `:160`) are similarly missing
  `doc(cfg(...))` annotations.

## 5. API design issues

- **`Uid::Random([u8; 4])` vs `Session::<Authenticated>::get_uid`** —
  `Session::get_selected_uid` returns `Uid` (fixed or random), but
  `Session::<Authenticated>::get_uid` (`authenticated.rs:145`) returns
  `[u8; 7]`. Two types for effectively the same concept. Either return `Uid`
  from both (with `as_fixed()` convenience), or make the asymmetry explicit
  in the doc ("this command is only issued after authentication, which
  implies a fixed 7‑byte UID").
- **`Transport::get_uid` contract is under‑specified** (`src/transport.rs:15`).
  It returns `Self::Data` of arbitrary length; the only caller
  (`Session::get_selected_uid`, `session/mod.rs:99‑113`) manually checks for
  4 or 7 bytes. Either document this contract on the trait, or move the
  length check into a default method
  (`fn get_uid(&mut self) -> impl Future<Output = Result<Uid, Self::Error>>`)
  with a lower‑level hook for raw bytes.
- **`Transport::Data: AsRef<[u8]>`** has no documented contract. Why an
  associated type rather than always `&[u8]` or `alloc::vec::Vec<u8>`? The
  `pcsc` crate motivates it, but it should be written down.
- **`Response` has `pub` fields** (`transport.rs:19‑23`). Consider adding a
  convenience `status(&self) -> ResponseStatus` accessor so users aren't
  forced to re‑implement the `(sw1 << 8) | sw2` match in every
  integration.
- **`SessionError` uses `#[from]` inconsistently** (`session/mod.rs:31‑63`):
  `Transport(#[from] E)` allows `?` to propagate transport errors, but
  `FileSettings(FileSettingsError)` and
  `OriginalityVerificationFailed(OriginalityError)` do not. Users
  `map_err` unnecessarily. Add `#[from]` where sensible.
- **No error enum is `#[non_exhaustive]`.** `SessionError`,
  `FileSettingsError`, `SdmError`, `SdmUrlError`, `CcError` — all are open
  to new variants becoming a breaking change. Mark them
  `#[non_exhaustive]` before 1.0. Particularly important for
  `FileSettingsError` and `SdmUrlError`, which are likely to grow.
- **`Sdm::try_new` skips overlap checks with the encrypted PICCData blob**
  (`types/file_settings.rs:571‑573, 605‑609`). This is an explicit
  landmine: a user can build a "validated" `Sdm` that is still structurally
  broken because the encrypted blob (32 or 48 bytes depending on
  `CryptoMode`) overlaps another placeholder. Either
  - take `CryptoMode` in `try_new` and do the check
    (`Sdm::try_new(picc, file_read, tt, CryptoMode::Aes)`), or
  - rename the entry point (`Sdm::try_new_without_picc_size_check`) and
    expose a `try_new_with_mode(..., CryptoMode)` that performs the full
    check.
    The current design pushes the responsibility onto the user, which is
    exactly what the `sdm_url_config!` macro is meant to hide — it should be
    hidden in the manual path too.
- **`Configuration::with_failed_auth_counter(true, 1000, 10)`**
  (`types/configuration.rs:123`) takes positional `(bool, u16, u16)`.
  Trivially easy to swap `limit` and `decrement`. Split into
  `.with_failed_auth_counter_enabled(limit, decrement)` and
  `.with_failed_auth_counter_disabled()`.
- **`Configuration` builder "last writer wins" semantics** aren't
  documented; calling `with_failed_auth_counter(true, …)` followed by
  `with_failed_auth_counter(false, …)` silently overwrites. Spell this out.
- **`FileSettingsPatch` uses naked `pub` fields** while `Configuration`
  uses a typed builder. Pick one pattern for "things you build to send to
  the tag". Since `Sdm::try_new` already does extensive validation,
  `FileSettingsPatch` with public fields is defensible — but then consider
  exposing `Configuration`'s fields too, so users aren't switching between
  styles in the same block of provisioning code.
- **`FileReadKey`** (`types/file_settings.rs:280‑290`) adds ceremony
  without enforcing an invariant: `FileReadKey::new(k)` accepts any
  `KeyNumber`. If the "Free / NoAccess" exclusion is meant to be
  structural, enforce it at construction; otherwise use `KeyNumber`
  directly.
- **Version capability helpers** — `has_tag_tamper_support()` is good, but
  there's no analogous `supports_lrp()` / `supports_originality()`. Hands‑on
  users will otherwise copy‑paste hex comparisons.

---

## Bottom line

The crate is on a good trajectory — strong typestate, careful validation,
excellent spec citations. Before a 1.0 I would prioritise, in order:

1. Document the **self‑consume rationale** on `Session<Authenticated<_>>`
   and then _consistently_ apply it (`read_file_with_mode` naming, plain
   vs MAC distinction written down — §3).
2. Close the **documentation gaps** on public fields, variants, and TODOs
   (§4.1–§4.3).
3. Make **`Sdm::try_new` overlap‑complete** or rename it so the current
   weak guarantee stops being a footgun (§5).
4. Clean up the **root re‑export surface** and the macro‑vs‑function name
   collision (§2).
5. Mark error enums **`#[non_exhaustive]`** for future‑proofing (§5).
