# Review: `ntag424` API & documentation

Target audience: a generalist Rust developer who has never read NT4H2421Gx. The
goal is a high-quality, stable API. The crate is well thought out, well cited
against the spec, and its feature‑gating / `no_std` hygiene is solid. What
follows are concrete things worth fixing before a 1.0, ordered by impact for a
hands‑on user.

---

## 1. API design issues

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
