/// This example shows how to provision a NTAG424 with a new master key, diversified keys and
/// SDM URL configuration. It uses the PC/SC interface, but the same logic applies to other
/// transports as well.
///
/// The provisioning process includes the following steps:
/// 1. Connect to the tag using a raw transport (PC/SC in this case).
/// 2. Authenticate using the factory default keys (all zeros).
/// 3. Verify originality using the tag's UID.
/// 4. Update the tag configuration (e.g. enable random UID mode etc.).
/// 5. Derive new keys from the master key and update them on the tag.
/// 6. Create the SDM / NDEF config and update the NDEF file content and settings.
/// 7. Update the master key
///
/// The tag can then be read using standard NFC readers. To verify the URL on the server side
/// you can use the `Verifier` returned by the `provision` function, which contains the necessary
/// information.
use anyhow::{Context as _, Result, bail};
use ntag424::{
    Access, AccessRights, AuthenticatedSession, CommMode, Configuration, EncryptedSession, File,
    FileSettingsUpdate, KeyNumber, NonMasterKeyNumber, OriginalitySignature, Session, Transport,
    Uid, Version,
    high_level::ApplicationVerifier,
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, Verifier, sdm_url_config},
};
use rand::{RngExt as _, rngs::StdRng};

use example_utils::{self as utils, ServerSideData};

/// A system identifier is used as additional input to the
/// key diversification function to derive the session keys
/// from the master key.
///
/// You may leave it empty if you do not need more than one
/// name space for your keys. If you want to use the same master key
/// for different applications, you should use a different system identifier
/// for each application.
const SYSTEM_IDENTIFIER: &[u8; 16] = b"provisionexample";

async fn check_tag<T: Transport>(transport: &mut T) -> Result<(Version, Uid)>
where
    T::Error: Send + Sync + 'static,
{
    let version = Session::new()
        .get_version(transport)
        .await
        .context("failed to get version")?;
    if version.hw_type() != 0x04 {
        bail!(
            "This does not seem to be a NTAG424 (hw_type = 0x{:02x})",
            version.hw_type()
        );
    }
    let selected_uid = Session::new()
        .get_selected_uid(transport)
        .await
        .context("failed to read UID")?;
    println!("Selected UID: {}", utils::hex(selected_uid.as_ref()));
    Ok((version, selected_uid))
}

async fn authenticate_and_verify_originality<T: Transport>(
    transport: &mut T,
    selected_uid: &Uid,
) -> Result<(EncryptedSession, [u8; 7], OriginalitySignature)>
where
    T::Error: Send + Sync + 'static,
{
    let session = utils::authenticate_using_factory_defaults(transport).await?;
    let (uid, session) = session
        .get_uid(transport)
        .await
        .context("failed to get UID")?;
    if selected_uid.is_random() {
        println!("UID: {}", utils::hex(&uid));
    }
    let (session, originality_sig) = session
        .verify_originality(transport, &uid)
        .await
        .context("originality verification failed")?;
    println!(
        "Originality signature: {}",
        utils::hex(originality_sig.as_bytes())
    );
    Ok((session, uid, originality_sig))
}

async fn configure_tag<T: Transport>(
    transport: &mut T,
    session: EncryptedSession,
    version: &Version,
    selected_uid: &Uid,
) -> Result<(EncryptedSession, bool)>
where
    T::Error: Send + Sync + 'static,
{
    let mut config = Configuration::new();
    if selected_uid.is_random() {
        println!("The tag is in random UID mode.");
    } else if utils::ask_user_confirm("Enable random UID mode permanently?")? {
        config = config.with_random_uid_enabled();
    }
    let tag_tamper_enabled = if version.has_tag_tamper_support()
        && utils::ask_user_confirm("Enable tag tamper feature permanently?")?
    {
        // chose stricter access permissions if needed
        config = config.with_tag_tamper_enabled(Access::Free);
        true
    } else {
        false
    };
    let mut session = session
        .set_configuration(transport, &config)
        .await
        .context("failed to set configuration")?;
    if tag_tamper_enabled {
        let (tt_status, new_session) = session
            .get_tt_status(transport)
            .await
            .context("failed to read tag tamper status")?;
        if tt_status.is_tampered() {
            bail!("The tag tamper detection triggered, the tag might be damaged, use a new one.");
        }
        session = new_session;
    }
    Ok((session, tag_tamper_enabled))
}

async fn provision_keys<T: Transport>(
    transport: &mut T,
    mut session: EncryptedSession,
    master_key: &[u8; 16],
    picc_key: &[u8; 16],
    uid: &[u8; 7],
) -> Result<EncryptedSession>
where
    T::Error: Send + Sync + 'static,
{
    // Key1 holds the cohort-fixed PICC encryption key (it must be the same on every tag,
    // so the server can decrypt PICC data before knowing the UID). Key2..Key4 are per-tag
    // diversified.
    for key_number in [
        NonMasterKeyNumber::Key1,
        NonMasterKeyNumber::Key2,
        NonMasterKeyNumber::Key3,
        NonMasterKeyNumber::Key4,
    ] {
        let new_key = if key_number == NonMasterKeyNumber::Key1 {
            *picc_key
        } else {
            diversify_ntag424(master_key, uid, key_number.into(), SYSTEM_IDENTIFIER)
        };
        println!("New key {key_number:?}: {}", utils::hex(&new_key));
        let old_key = [0u8; 16]; // factory default key
        session = session
            .change_key(transport, key_number, &new_key, 0x01, &old_key)
            .await
            .context(format!("failed to change key {key_number:?}"))?;
    }
    Ok(session)
}

async fn configure_ndef<T: Transport>(
    transport: &mut T,
    mut session: EncryptedSession,
    master_key: &[u8; 16],
    tag_tamper_enabled: bool,
    uid: [u8; 7],
    originality_signature: OriginalitySignature,
) -> Result<ApplicationVerifier>
where
    T::Error: Send + Sync + 'static,
{
    let default = if tag_tamper_enabled {
        "https://example.com/?id=[[{picc:uid+ctr}&tt=[{tt}]&mac={mac}"
    } else {
        "https://example.com/?id=[[{picc:uid+ctr}&mac={mac}"
    };
    let template = utils::ask_user_input("Enter the NDEF URL template:", default)?;
    let sdm_url_config = sdm_url_config(
        &template,
        session.mode(),
        SdmUrlOptions {
            // The PICC data contains the UID and read counter encrypted with the PICC key.
            // The verifier must decrypt this before knowing the UID, so the PICC key has
            // to be cohort-fixed rather than per-tag diversified. We use Key1 for that;
            // keeping it separate from Key0 means a leak of the PICC key does not also
            // grant master-key admin authority. The MAC key (default `mac_key = Key2`)
            // remains per-tag diversified.
            picc_key: KeyNumber::Key1,
            mac_key: KeyNumber::Key2,
            ..Default::default()
        },
    )
    .context("failed to create SDM URL config")?;
    let sdm = sdm_url_config.sdm_settings;
    let verifier =
        Verifier::try_new(&sdm, session.mode()).context("failed to create SDM URL verifier")?;
    session = session
        .write_file(transport, File::Ndef, 0, &sdm_url_config.ndef_bytes)
        .await
        .context("failed to write NDEF file")?;
    session = session
        .change_file_settings(
            transport,
            File::Ndef,
            &FileSettingsUpdate::new(
                // Needed for standard readers
                CommMode::Plain,
                AccessRights {
                    // Needed for standard readers
                    read: Access::Free,
                    // Lock down write and change
                    write: Access::NoAccess,
                    read_write: Access::Key(KeyNumber::Key0),
                    change: Access::Key(KeyNumber::Key0),
                },
            )
            .with_sdm(sdm),
        )
        .await
        .context("failed to update NDEF file settings")?;
    session
        .change_master_key(transport, master_key, 0x01)
        .await
        .context("failed to change master key")?;

    Ok(ApplicationVerifier {
        url_template: template,
        verifier,
        prefix: sdm_url_config.prefix().map(|p| p.to_vec()),
        system_identifier: SYSTEM_IDENTIFIER.to_vec(),
        uid: Some(uid),
        originality_signature: Some(originality_signature),
    })
}

async fn provision<T: Transport>(
    mut transport: T,
    master_key: &[u8; 16],
    picc_key: &[u8; 16],
) -> Result<ApplicationVerifier>
where
    T::Error: Send + Sync + 'static,
{
    // WARN: Printing is for demo purposes only,
    //       never print or log sensitive data such as keys in a real application.
    let (version, selected_uid) = check_tag(&mut transport).await?;
    let (session, uid, originality_sig) =
        authenticate_and_verify_originality(&mut transport, &selected_uid).await?;
    let (session, tag_tamper_enabled) =
        configure_tag(&mut transport, session, &version, &selected_uid).await?;
    let session = provision_keys(&mut transport, session, master_key, picc_key, &uid).await?;
    configure_ndef(
        &mut transport,
        session,
        master_key,
        tag_tamper_enabled,
        uid,
        originality_sig,
    )
    .await
}

fn main() -> Result<()> {
    let transport = utils::get_pcsc_transport()?;
    let mut rng: StdRng = rand::make_rng();

    // WARN: Generate and store these keys securely; this is only a demo.
    //       In production both keys are cohort-wide secrets loaded from a vault,
    //       not freshly randomized per run.
    let master_key: [u8; 16] = rng.random();
    let picc_key: [u8; 16] = rng.random();
    println!("New master key: {}", utils::hex(&master_key));
    println!("New PICC key:   {}", utils::hex(&picc_key));

    let application_verifier = utils::block_on(provision(transport, &master_key, &picc_key))?;

    println!("Provisioning successful.");

    let server_data = ServerSideData {
        // NOTE: The verifier information is needed on the server side
        //       to verify the NDEF URL read from the tag.
        //
        // It contains information about the placeholders and keys used for encryption and MAC.
        // The server must load this information from a trusted source (e.g. a database or vault)
        // or have it hardcoded.
        application_verifier,
        // WARN: In a real application, you do not print or serialize keys
        master_key,
        picc_key,
    };

    println!(
        "Paste the following data into the verification example, the NDEF file will be read from the tag.\n"
    );

    serde_json::to_writer_pretty(std::io::stdout(), &server_data)
        .context("failed to serialize server-side data")?;

    Ok(())
}
