# NTAG 424 DNA — Use of LRP Primitives

This note summarises where the LRP primitives implemented in `ntag424core::lrp`
are actually called by the NTAG 424 DNA protocol (NT4H2421Gx, rev 3.0). It
only covers LRP mode; AES mode uses AES‑CBC / AES‑CMAC in the same places.

LRP mode is permanently enabled via `SetConfiguration` and entered with
`AuthenticateLRPFirst` / `AuthenticateLRPNonFirst`. From then on, every
AES‑CBC call is replaced by `LRICBEnc` / `LRICBDec`, and every AES‑CMAC
call is replaced by `MAC_LRP` (AN12304 §2.4). LRICB is used *only* for
confidentiality; authentication and key derivation use `eval_lrp` / CMAC.

## Session key derivation (§9.2.7)

After `AuthenticateLRPFirst`:

```
Kx           = AppKey targeted by the authentication
SV           = 00 01 00 80 RndA[15..14] (RndA[13..8] ^ RndB[15..10]) RndB[9..0] RndA[7..0] 96 69
SesAuthMasterKey = MAC_LRP(Kx, SV)
SesAuthENCKey / SesAuthMACKey = generatePlaintexts(4, SesAuthMasterKey) + generateUpdatedKeys(2, …)
```

A session “key” is therefore the (plaintexts, updatedKey) pair — exactly
what `Lrp::from_parts` takes.

## Where LRICB is invoked

| Context | Key | Counter / IV |
|---|---|---|
| CommMode.Full cmd/resp payloads (§9.2.4) | `SesAuthENCKey` | 32‑bit `EncCtr`, reset at auth; `AuthLRPFirst` starts SM at `EncCtr = 1` because `0` was used for the part‑2 response |
| `AuthenticateLRPFirst` part 2 response (§9.2.5) | `SesAuthENCKey` | `EncCtr = 0`; encrypts `TI ‖ PDcap2 ‖ PCDcap2` |
| Encrypted PICCData mirror for SDM (§9.3.4.2) | `SDMMetaReadKey` directly | 8‑byte random `PICCRand`, mirrored in plain alongside the ciphertext |
| Encrypted file data mirror `SDMENCFileData` (§9.3.6.2) | `SesSDMFileReadENCKey` | 6‑byte counter `SDMReadCtr ‖ 00 00 00`, LSB first |

Padding in all cases is ISO/IEC 9797‑1 Method 2 (`80 00 … 00`), except during
the authentication exchange itself where no padding is applied.

`EncCtr` is MSB‑first for the key‑stream calculation and increases by the
number of 16‑byte blocks processed (data + padding).

## Where LRP‑CMAC is invoked

- Session‑key KDF (§9.2.7, §9.3.9.2): `MAC_LRP(Kx, SV)`.
- Command / response MAC in CommMode.MAC and CommMode.Full (§9.2.3):
  `MAC_LRP(SesAuthMACKey, Cmd ‖ CmdCtr ‖ TI ‖ CmdHeader ‖ CmdData)` truncated
  to the 8 even‑indexed bytes.
- `SDMMAC` for SDM reads (§9.3.8.2): same truncation, key
  `SesSDMFileReadMACKey`.

## Mapping to `ntag424core::lrp`

- `eval_lrp` — underlying block function (§2.2 of AN12304).
- `Lrp` cipher type (`impl BlockCipherEncrypt`) — plugs into
  `cmac::Cmac<Lrp>` to give `MAC_LRP`.
- `Lrp::lricb_encrypt_into` / `Lrp::lricb_decrypt_into` — the `LRICBEnc` /
  `LRICBDec` used in all four encryption contexts above. Take a `&mut [u8]`
  counter that is post‑incremented by the number of processed blocks (matches
  the `EncCtr` rule of §9.2.4). With the default `alloc` feature, the
  `Lrp::lricb_encrypt` / `Lrp::lricb_decrypt` wrappers allocate the output
  `Vec<u8>`.
- `generate_plaintexts` / `generate_updated_keys` — build the session key
  material from `SesAuthMasterKey` and the SDM master keys.
