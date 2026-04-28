use anyhow::{Context as _, Result, bail};
use ntag424::{EncryptedSession, Session, Transport};
use ntag424_pcsc::CardTransport;
use pcsc::{Context, Protocols, Scope};
use rand::{RngExt as _, rngs::StdRng};

/// List available PC/SC readers and let the user select one.
pub fn get_pcsc_transport() -> Result<CardTransport> {
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
pub async fn authenticate_using_factory_defaults<T: Transport>(
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
        let enable_lrp = ask_user_confirm(
            "AES authentication succeeded. Do you want to enable LRP crypto mode permanently?",
        )?;
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

/// A simple executor that runs a future to completion.
///
/// This only supports futures that are immediately ready.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("block_on: future yielded"),
    }
}

pub fn ask_user_confirm(prompt: &str) -> Result<bool> {
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .interact()
        .context("failed to read input")
}

pub fn ask_user_input(prompt: &str, default: &str) -> Result<String> {
    dialoguer::Input::<String>::new()
        .with_prompt(prompt)
        .default(default.to_string())
        .interact()
        .context("failed to read input")
}

/// Format bytes as a hex string, e.g. "DE AD BE EF".
pub fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn ascii_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                format!(" {}", b as char)
            } else {
                format!("{:02X}", b)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
