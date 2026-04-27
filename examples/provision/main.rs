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
    FileSettingsUpdate, KeyNumber, NonMasterKeyNumber, Session, Transport,
    key_diversification::diversify_ntag424,
    sdm::{SdmUrlOptions, Verifier, sdm_url_config},
};
use ntag424_pcsc::CardTransport;
use pcsc::{Context, Protocols, Scope};
use rand::{RngExt as _, rngs::StdRng};

/// List available PC/SC readers and let the user select one.
fn get_pcsc_transport() -> Result<CardTransport> {
    let ctx = Context::establish(Scope::User)
        .context("failed to establish context, is PC/SC installed and configured correctly?")?;
    let len = ctx
        .list_readers_len()
        .context("failed to get readers buffer size")?;
    let mut readers_buf = vec![0u8; len];
    let readers: Vec<_> = ctx
        .list_readers(&mut readers_buf)
        .context("failed to list readers")?
        .collect();

    if readers.is_empty() {
        bail!("No readers found.");
    }

    let sel = dialoguer::Select::new()
        .with_prompt("Select a reader")
        .items(
            readers
                .iter()
                .map(|r| r.to_string_lossy())
                .collect::<Vec<_>>(),
        )
        .interact()
        .context("failed to select reader")?;

    let card = ctx
        .connect(readers[sel], pcsc::ShareMode::Shared, Protocols::ANY)
        .context("failed to connect to reader")?;
    Ok(CardTransport { card })
}

/// Try to authenticate using the factory default keys (all zeros).
async fn authenticate_using_factory_defaults<T: Transport>(
    transport: &mut T,
) -> Result<EncryptedSession>
where
    T::Error: Send + Sync + 'static,
{
    let mut rng: StdRng = rand::make_rng();
    // first check if AES authentication with factory default keys works
    if let Ok(s) = Session::new()
        .authenticate_aes(transport, ntag424::KeyNumber::Key0, &[0; 16], rng.random())
        .await
    {
        let enable_lrp = dialoguer::Confirm::new()
            .with_prompt(
                "AES authentication succeeded. Do you want to enable LRP crypto mode permanently?",
            )
            .interact()
            .context("failed to read input")?;
        if enable_lrp {
            s.enable_lrp(transport)
                .await
                .context("failed to enable LRP mode")?;
            // Fall through to authentication using factory defaults with LRP,
            // which should succeed now that it's enabled.
        } else {
            return Ok(s.into());
        }
    }
    Ok(Session::new()
        .authenticate_lrp(transport, ntag424::KeyNumber::Key0, &[0; 16], rng.random())
        .await
        .context("failed to authenticate with factory keys")?
        .into())
}

/// A system identifier is used as additional input to the
/// key diversification function to derive the session keys
/// from the master key.
///
/// You may leave it empty if you do not need more than one
/// name space for your keys. If you want to use the same master key
/// for different applications, you should use a different system identifier
/// for each application to avoid key collisions.
const SYSTEM_IDENTIFIER: &[u8; 16] = b"provisionexample";

async fn provision<T: Transport>(
    mut transport: T,
    master_key: &[u8; 16],
    picc_key: &[u8; 16],
) -> Result<Verifier>
where
    T::Error: Send + Sync + 'static,
{
    // WARN: Printing is for demo purposes only,
    //       never print or log sensitive data such as keys in a real application.

    // Check if this seems to be a NTAG424
    let version = Session::new()
        .get_version(&mut transport)
        .await
        .context("failed to get version")?;
    if version.hw_type() != 0x04 {
        bail!(
            "This does not seem to be a NTAG424 (hw_type = 0x{:02x})",
            version.hw_type()
        );
    }
    let selected_uid = Session::new()
        .get_selected_uid(&mut transport)
        .await
        .context("failed to read UID")?;
    println!("Selected UID: {}", hex(selected_uid.as_ref()));

    // Try to authenticate using the default key (all zeros)
    let session = authenticate_using_factory_defaults(&mut transport).await?;

    // Check originality
    let (uid, session) = session
        .get_uid(&mut transport)
        .await
        .context("failed to get UID")?;
    if selected_uid.is_random() {
        println!("UID: {}", hex(uid.as_ref()));
    }
    let session = session
        .verify_originality(&mut transport, &uid)
        .await
        .context("originality verification failed")?;

    // Update configuration
    let mut config = Configuration::new();
    if selected_uid.is_random() {
        println!("The tag is in random UID mode.");
    } else if dialoguer::Confirm::new()
        .with_prompt("Enable random UID mode permanently?")
        .interact()
        .context("failed to read input")?
    {
        config = config.with_random_uid_enabled();
    }
    let tag_tamper_enabled = if version.has_tag_tamper_support()
        && dialoguer::Confirm::new()
            .with_prompt("Enable tag tamper feature permanently?")
            .interact()
            .context("failed to read input")?
    {
        // chose stricter access permissions if needed
        config = config.with_tag_tamper_enabled(Access::Free);
        true
    } else {
        false
    };
    let mut session = session
        .set_configuration(&mut transport, &config)
        .await
        .context("failed to set configuration")?;

    if tag_tamper_enabled {
        let (tt_status, new_session) = session
            .get_tt_status(&mut transport)
            .await
            .context("failed to read tag tamper status")?;
        if tt_status.is_tampered() {
            bail!("The tag tamper detection triggered, the tag might be damaged, use a new one.");
        }
        session = new_session;
    }

    // Provision Key1..Key4. Key1 holds the cohort-fixed PICC encryption key
    // (it must be the same on every tag, so the server can decrypt PICC data
    // before knowing the UID). Key2..Key4 are per-tag diversified.
    for key_number in [
        NonMasterKeyNumber::Key1,
        NonMasterKeyNumber::Key2,
        NonMasterKeyNumber::Key3,
        NonMasterKeyNumber::Key4,
    ] {
        let new_key = if key_number == NonMasterKeyNumber::Key1 {
            *picc_key
        } else {
            diversify_ntag424(master_key, &uid, key_number.into(), SYSTEM_IDENTIFIER)
        };
        println!("New key {key_number:?}: {}", hex(&new_key));
        let new_key_version = 0x01; // free to choose
        let old_key = [0u8; 16]; // factory default key
        session = session
            .change_key(
                &mut transport,
                key_number,
                &new_key,
                new_key_version,
                &old_key,
            )
            .await
            .context(format!("failed to change key {key_number:?}"))?;
    }

    // Create the SDM / NDEF config
    let default = if tag_tamper_enabled {
        "[[https://example.com/?id={picc:uid+ctr}&tt=[{tt}]&mac={mac}"
    } else {
        "[[https://example.com/?id={picc:uid+ctr}&mac={mac}"
    };
    let template = dialoguer::Input::<String>::new()
        .with_prompt("Enter the NDEF URL template:")
        .default(default.to_string())
        .interact()
        .context("failed to read input")?;
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
            ..Default::default()
        },
    )
    .context("failed to create SDM URL config")?;
    let sdm = sdm_url_config.sdm_settings;
    let verifier =
        Verifier::try_new(&sdm, session.mode()).context("failed to create SDM URL verifier")?;

    // Update the NDEF file content
    session = session
        .write_file(&mut transport, File::Ndef, 0, &sdm_url_config.ndef_bytes)
        .await
        .context("failed to write NDEF file")?;

    // Update the NDEF file settings
    session = session
        .change_file_settings(
            &mut transport,
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

    // Update master key, destroys session
    let new_key_version = 0x01; // free to choose
    session
        .change_master_key(&mut transport, master_key, new_key_version)
        .await
        .context("failed to change master key")?;

    Ok(verifier)
}

fn main() -> Result<()> {
    let transport = get_pcsc_transport()?;
    let mut rng: StdRng = rand::make_rng();

    // WARN: Generate and store these keys securely; this is only a demo.
    //       In production both keys are cohort-wide secrets loaded from a vault,
    //       not freshly randomized per run.
    let master_key: [u8; 16] = rng.random();
    let picc_key: [u8; 16] = rng.random();
    println!("New master key: {}", hex(&master_key));
    println!("New PICC key:   {}", hex(&picc_key));

    let verifier = block_on(provision(transport, &master_key, &picc_key))?;
    // The verifier can be used to verify the URL on the server,
    // with the 'serde' feature you may serialize and store it.

    println!("Provisioning successful.");
    Ok(())
}

/// A simple executor that runs a future to completion.
///
/// This only supports futures that are immediately ready.
fn block_on<F: Future>(fut: F) -> F::Output {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("block_on: future yielded"),
    }
}

/// Format bytes as a hex string, e.g. "DE AD BE EF".
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
