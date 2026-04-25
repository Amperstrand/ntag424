# Review: `ntag424` API & documentation

Target audience: a generalist Rust developer who has never read NT4H2421Gx. The
goal is a high-quality, stable API. The crate is well thought out, well cited
against the spec, and its feature‑gating / `no_std` hygiene is solid. What
follows are concrete things worth fixing before a 1.0, ordered by impact for a
hands‑on user.

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

### 4.2 Missing per‑item docs on public fields / variants

Hands‑on users lean heavily on rustdoc for struct fields. The following
public fields are undocumented:

- `src/types/uid.rs:10‑11` — `Uid::Fixed([u8; 7])`, `Uid::Random([u8; 4])`.
  The outer doc (`:1‑7`) says the random variant's leading byte is `0x08`
  per ISO/IEC 14443‑3 but doesn't tell the reader whether that `0x08` is
  included in the 4 bytes.
- `src/types/tt_status.rs:14` — `TagTamperStatus::Unknown(u8)` has no doc
  on what byte values can end up there.

## 5. API design issues

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
