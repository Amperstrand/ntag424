pub struct Session<S> {
    state: S,
}

impl Session<Unauthenticated> {
    pub fn new() -> Self {
        Self {
            state: Unauthenticated,
        }
    }
}

impl Default for Session<Unauthenticated> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Unauthenticated;

pub struct AwaitingAuthChallenge {
    rnd_a: [u8; 16],
    key: [u8; 16],
}

pub struct Authenticated {
    session_key: [u8; 16],
    session_mac: [u8; 16],
    cmd_counter: u16,
    /// Transaction identifier, incremented on each command.
    ///
    /// Used to prevent replay attacks.
    ti: [u8; 4],
}
