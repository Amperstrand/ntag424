//! Configuration payloads for the `SetConfiguration` command (NT4H2421Gx
//! §10.5.1, Tables 49 and 50).

/// Builder for the `SetConfiguration` data payload.
///
/// Each option (PICC, secure messaging, capability, failed-authentication
/// counter, HW) is independent and only emitted on the wire if the caller
/// explicitly set it through one of the `with_*` methods. Unset options are
/// omitted, so the corresponding tag-side configuration stays unchanged.
#[derive(Debug, Default, Clone)]
pub struct Configuration {
    picc: Option<[u8; 1]>,
    secure_messaging: Option<[u8; 2]>,
    capability: Option<[u8; 10]>,
    failed_auth_counter: Option<[u8; 5]>,
    hw: Option<[u8; 1]>,
}

impl Configuration {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable Random UID mode (PICCConfig bit 1).
    ///
    /// <div class="warning">This change is <strong>permanent</strong>.</div>
    ///
    /// Depending on tag usage this feature may help to fulfill GDPR regulations
    /// regarding personal tracking and personal data.
    ///
    /// If you use [derived keys](`crate::key_diversification`) based on the UID, be aware that
    /// you can no longer read the real UID _before_ authentication, which
    /// should be considered in your key diversification and provisioning strategy.
    pub fn with_random_uid_enabled(mut self) -> Self {
        // TODO: extend docs, briefly explain the consequences
        let bytes = self.picc.get_or_insert([0]);
        bytes[0] |= 1 << 1;
        self
    }

    /// Disable chained writes.
    ///
    /// <div class="warning">This change is <strong>permanent</strong>.</div>
    ///
    /// Sets SMConfig bit 2 for `WriteData` in `CommMode.MAC` and
    /// `CommMode.Full`.
    pub fn with_chained_writing_disabled(mut self) -> Self {
        // TODO: extend docs, briefly explain the consequences
        let bytes = self.secure_messaging.get_or_insert([0; 2]);
        // SMConfig is two bytes; bit 2 lives in the low byte.
        bytes[0] |= 1 << 2;
        self
    }

    /// Enable LRP (Leakage Resilient Primitive) mode (PDCap2.1 bit 1).
    ///
    /// This change is **permanent** — once enabled, LRP cannot be disabled
    /// (NT4H2421Gx §8, "After this switch, it is not possible to revert back
    /// to AES mode").
    ///
    /// The switch is exposed only to the crate because it must not be mixed
    /// with other `SetConfiguration` options: enabling LRP tears down the
    /// current secure channel on the PICC (the PICC returns `9100` without
    /// a response `MACt`, and any subsequent secure-messaging command fails
    /// with `LENGTH_ERROR` / `PERMISSION_DENIED`). Callers go through
    /// `Session<Authenticated<AesSuite>>::enable_lrp`, which performs the
    /// single-option APDU and yields a fresh unauthenticated session.
    ///
    /// AES vs. LRP is negotiated only on First Authentication via
    /// `PCDCap2.1` / `PDCap2.1` (NT4H2421Gx §9.1.4, Table 19); after the
    /// session is reset the PICC rejects `AuthenticateEV2First` with
    /// `PERMISSION_DENIED` and only accepts `AuthenticateLRPFirst`.
    pub(crate) fn with_lrp_enabled(mut self) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[4] |= 1 << 1;
        self
    }

    /// Set the user-configured `PDCap2.5` capability byte.
    pub fn with_pdcap2_5(mut self, byte: u8) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[8] = byte;
        self
    }

    /// Set the user-configured `PDCap2.6` capability byte.
    pub fn with_pdcap2_6(mut self, byte: u8) -> Self {
        let bytes = self.capability.get_or_insert([0; 10]);
        bytes[9] = byte;
        self
    }

    /// Configure the failed-authentication counter.
    ///
    /// `limit` must be non-zero when `enabled` is true (tag default: 1000);
    /// `decrement` is the amount subtracted on each successful authentication
    /// (tag default: 10). Both values are ignored by the tag when `enabled`
    /// is false.
    pub fn with_failed_auth_counter(mut self, enabled: bool, limit: u16, decrement: u16) -> Self {
        let mut bytes = [0u8; 5];
        bytes[0] = u8::from(enabled);
        bytes[1..3].copy_from_slice(&limit.to_le_bytes());
        bytes[3..5].copy_from_slice(&decrement.to_le_bytes());
        self.failed_auth_counter = Some(bytes);
        self
    }

    /// Configure HW back modulation: `true` for Strong (factory default),
    /// `false` for Standard. The datasheet recommends keeping the default for
    /// antennas smaller than Class 1.
    pub fn with_strong_back_modulation(mut self, strong: bool) -> Self {
        self.hw = Some([u8::from(strong)]);
        self
    }

    /// Iterate over configured options in wire order.
    ///
    /// Yields `(option_id, payload)` pairs in the canonical Table 50
    /// order. Options that were never set are skipped.
    pub(crate) fn build(&self) -> impl Iterator<Item = (u8, &[u8])> {
        [
            (0x00u8, self.picc.as_ref().map(|b| b.as_slice())),
            (0x04, self.secure_messaging.as_ref().map(|b| b.as_slice())),
            (0x05, self.capability.as_ref().map(|b| b.as_slice())),
            (
                0x0A,
                self.failed_auth_counter.as_ref().map(|b| b.as_slice()),
            ),
            (0x0B, self.hw.as_ref().map(|b| b.as_slice())),
        ]
        .into_iter()
        .filter_map(|(id, data)| data.map(|d| (id, d)))
    }
}
