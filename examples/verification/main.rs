use std::collections::HashMap;

use anyhow::{Context as _, Result};
use ntag424::{File, KeyNumber, Session, key_diversification::diversify_ntag424, sdm::Verifier};
use serde::Deserialize;

use example_utils as utils;

#[derive(Deserialize)]
struct ServerSideData {
    verifier: Verifier,
    master_key: [u8; 16],
    picc_key: [u8; 16],
    system_identifier: Vec<u8>,
}

fn get_file_read_key(server_side: &ServerSideData, ndef: &[u8]) -> Result<[u8; 16]> {
    // decrypt_picc_data is called here (and again internally by verify_with_meta_key)
    // because we need the UID to derive the per-tag file-read key before calling verify.
    let (uid, _) = server_side
        .verifier
        .decrypt_picc_data(ndef, &server_side.picc_key)?;
    let Some(uid) = uid else {
        anyhow::bail!("PICC data does not contain a UID");
    };
    let file_read_key = match server_side.verifier.file_read_key() {
        KeyNumber::Key0 => server_side.master_key,
        // Key1 is the undiversified PICC meta-read key in this example's setup.
        KeyNumber::Key1 => server_side.picc_key,
        key => diversify_ntag424(
            &server_side.master_key,
            &uid,
            key,
            &server_side.system_identifier,
        ),
    };
    Ok(file_read_key)
}

fn main() -> Result<()> {
    let server_side_data = dialoguer::Input::<String>::new()
        .with_prompt("Enter the server-side data as JSON")
        .interact_text()?;
    let server_side_data: ServerSideData = serde_json::from_str(&server_side_data)?;

    let mut transport = utils::get_pcsc_transport()?;

    // Tracks the last-seen read counter per UID to detect replays.
    // A real server must persist this map across sessions and reject any
    // counter that is not strictly greater than the stored value for that UID.
    let mut read_counters: HashMap<[u8; 7], u32> = HashMap::new();

    loop {
        // This uses standard NFC Forum Type 4 Tag commands that do not require authentication,
        // mimicking what a standard NFC reader, e.g. a phone, would do.
        let mut ndef = vec![0u8; 256];
        let size = utils::block_on(Session::new().read_file_unauthenticated(
            &mut transport,
            File::Ndef,
            0,
            &mut ndef,
        ))?;
        ndef.truncate(size);
        println!("NDEF message: {:#?}", utils::ascii_hex(&ndef));

        // The Verifier offsets are relative to the raw NDEF file bytes
        // (the 7-byte NFC Type 4 wrapper is already accounted for internally).

        let file_read_key = get_file_read_key(&server_side_data, &ndef)
            .context("failed to derive file read key")?;
        let result = server_side_data.verifier.verify_with_meta_key(
            &ndef,
            &file_read_key,
            &server_side_data.picc_key,
        );

        match result {
            Ok(result) => {
                println!("Parsed NDEF message!");
                let uid_hex: String = result
                    .uid
                    .map_or_else(|| "N/A".to_string(), |u| u.iter().map(|b| format!("{b:02x}")).collect());
                println!("UID: {uid_hex}");
                if let (Some(uid), Some(read_ctr_ndef)) = (result.uid, result.read_ctr) {
                    let prev = read_counters.get(&uid).copied().unwrap_or(0);
                    if read_ctr_ndef <= prev {
                        println!(
                            "Warning: read counter did not increase ({} <= {})",
                            read_ctr_ndef, prev
                        );
                    } else {
                        println!("Read counter increased: {} -> {}", prev, read_ctr_ndef);
                        // NOT '+= 1'!
                        read_counters.insert(uid, read_ctr_ndef);
                    }
                }
            }
            Err(e) => println!("Verification failed: {e}"),
        }

        if !utils::ask_user_confirm("Continue?")? {
            break;
        }
    }
    Ok(())
}
