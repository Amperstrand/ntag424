// SPDX-FileCopyrightText: 2026 Jannik Schürg
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

/// Software, hardware, and production information about the tag.
///
/// See [Session](`crate::Session::get_version`) for how to obtain this information from the tag.
#[derive(Debug)]
pub struct Version {
    pub(crate) part1: [u8; 7],
    pub(crate) part2: [u8; 7],
    // Byte 15 is optional, present for customized configurations when FabKey = 1Fh
    pub(crate) part3: [u8; 14],
}

impl Version {
    // Part 1 - Hardware related information

    pub fn hw_vendor_id(&self) -> u8 {
        self.part1[0]
    }

    pub fn hw_type(&self) -> u8 {
        self.part1[1]
    }

    pub fn hw_sub_type(&self) -> u8 {
        self.part1[2]
    }

    /// Returns whether the hardware subtype indicates Tag Tamper-capable silicon.
    pub fn has_tag_tamper_support(&self) -> bool {
        self.hw_sub_type() & 0x0F == 0x08
    }

    pub fn hw_major_version(&self) -> u8 {
        self.part1[3]
    }

    pub fn hw_minor_version(&self) -> u8 {
        self.part1[4]
    }

    pub fn hw_storage_size(&self) -> u8 {
        self.part1[5]
    }

    pub fn hw_protocol_type(&self) -> u8 {
        self.part1[6]
    }

    // Part 2 - Software related information

    pub fn sw_vendor_id(&self) -> u8 {
        self.part2[0]
    }

    pub fn sw_type(&self) -> u8 {
        self.part2[1]
    }

    pub fn sw_sub_type(&self) -> u8 {
        self.part2[2]
    }

    pub fn sw_major_version(&self) -> u8 {
        self.part2[3]
    }

    pub fn sw_minor_version(&self) -> u8 {
        self.part2[4]
    }

    pub fn sw_storage_size(&self) -> u8 {
        self.part2[5]
    }

    pub fn sw_protocol_type(&self) -> u8 {
        self.part2[6]
    }

    // Part 3 - Production related information

    /// The 7-byte UID of the tag. For tags in random-ID mode, this is the
    /// randomized ID.
    ///
    /// Use [`Session::get_uid`](`crate::Session::get_uid`) to obtain the real UID on random-ID tags.
    pub fn uid(&self) -> &[u8; 7] {
        // TODO: clarify padding for random ID which are shorter
        // TODO: reference `get_uid` for real UID on random-ID tags once implemented
        (&self.part3[0..7])
            .try_into()
            .expect("slice with incorrect length")
    }

    pub fn batch_number(&self) -> &[u8; 4] {
        // TODO: BE or LE int or what?
        (&self.part3[7..11])
            .try_into()
            .expect("slice with incorrect length")
    }

    /// Calendar week of production.
    pub fn calendar_week_of_production(&self) -> u8 {
        // Bit 7 of the raw byte is the DefaultFabKey flag; bits 6-0 are the BCD week,
        // NT3H2421Gx §10.5.2, Table 58.
        bcd_decode(self.part3[12] & 0b0111_1111)
    }

    // pub fn default_fab_key(&self) -> bool {
    //     self.part3[12] & 0b0100_0000 != 0
    // }

    /// Calendar year of production as the last two decimal digits.
    ///
    /// For example 26 corresponds to year 2026.
    pub fn calendar_year_of_production(&self) -> u8 {
        bcd_decode(self.part3[13])
    }
}

/// Decode a BCD-encoded byte into its decimal value (e.g. `0x26` → `26`).
fn bcd_decode(byte: u8) -> u8 {
    (byte >> 4) * 10 + (byte & 0x0F)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_with_hw_sub_type(hw_sub_type: u8) -> Version {
        Version {
            part1: [0x00, 0x00, hw_sub_type, 0x00, 0x00, 0x00, 0x00],
            part2: [0x00; 7],
            part3: [0x00; 14],
        }
    }

    #[test]
    fn tag_tamper_detection_accepts_both_back_modulation_variants() {
        assert!(version_with_hw_sub_type(0x08).has_tag_tamper_support());
        assert!(version_with_hw_sub_type(0x88).has_tag_tamper_support());
    }

    #[test]
    fn tag_tamper_detection_rejects_non_tt_low_nibbles() {
        assert!(!version_with_hw_sub_type(0x02).has_tag_tamper_support());
        assert!(!version_with_hw_sub_type(0x82).has_tag_tamper_support());
    }

    #[test]
    fn tag_tamper_detection_looks_at_the_x8h_suffix_not_the_high_nibble() {
        assert!(version_with_hw_sub_type(0x08).has_tag_tamper_support());
        assert!(!version_with_hw_sub_type(0x80).has_tag_tamper_support());
    }
}
