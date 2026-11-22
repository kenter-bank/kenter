use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use tracing::{debug, info};

use crate::apdu;
use crate::error::{KeycardError, Result};

/// Application info returned by SELECT.
#[derive(Debug, Clone)]
pub struct ApplicationInfo {
    /// Whether the applet has been INIT'd (PIN/PUK/pairing set). When false, the
    /// card returns only its secure-channel public key (bare tag 0x80) and the
    /// other fields below are not yet meaningful — run INIT first.
    pub initialized: bool,
    /// Unique instance identifier (16 bytes). Empty on an uninitialized card.
    pub instance_uid: Vec<u8>,
    /// Card's static secp256k1 public key (65 bytes, uncompressed). Always present.
    pub secure_channel_public_key: Vec<u8>,
    /// Applet version (major, minor). (0, 0) on an uninitialized card.
    pub app_version: (u8, u8),
    /// Number of remaining pairing slots. 0 / unknown on an uninitialized card.
    pub remaining_pairing_slots: u8,
    /// Whether a master key is loaded (only meaningful once initialized).
    pub key_initialized: bool,
    /// PIN attempts left, when the card reports them (tag `8C`, low nibble).
    ///
    /// `None` on a stock card, which does not send the status byte in SELECT.
    /// Worth surfacing because the number is actionable: a holder with one
    /// attempt left should be told before they spend it.
    pub pin_retries: Option<u8>,
}

/// A raw APDU transport — a PC/SC card, the jcardsim TCP server, etc. The secure
/// channel and command set are written against this so the same code runs on
/// hardware and in the simulator.
pub trait CardTransport {
    /// Send a command APDU, return the full response (`data ‖ SW1 SW2`).
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
}

/// Manages the PC/SC connection to a Keycard.
pub struct Transport {
    card: Card,
    recv_buf: Vec<u8>,
}

impl CardTransport for Transport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        Transport::transmit(self, apdu)
    }
}

impl Transport {
    /// Find the first available reader with a card present and connect.
    pub fn connect() -> Result<Self> {
        let ctx = Context::establish(Scope::System)?;

        let mut readers_buf = vec![0u8; 4096];
        let readers: Vec<&std::ffi::CStr> = ctx.list_readers(&mut readers_buf)?.collect();

        if readers.is_empty() {
            return Err(KeycardError::NoReader);
        }

        info!("found {} reader(s)", readers.len());
        for r in &readers {
            debug!("  reader: {:?}", r);
        }

        // Try each reader until we find one with a card
        let mut last_err = KeycardError::NoCard;
        for reader in &readers {
            match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                Ok(card) => {
                    info!("connected to reader: {:?}", reader);
                    return Ok(Self {
                        card,
                        recv_buf: vec![0u8; 1024],
                    });
                }
                Err(e) => {
                    debug!("reader {:?}: {}", reader, e);
                    last_err = e.into();
                }
            }
        }

        Err(last_err)
    }

    /// Connect to a specific reader by name substring.
    pub fn connect_to(reader_match: &str) -> Result<Self> {
        let ctx = Context::establish(Scope::System)?;

        let mut readers_buf = vec![0u8; 4096];
        let readers: Vec<&std::ffi::CStr> = ctx.list_readers(&mut readers_buf)?.collect();

        for reader in &readers {
            let name = reader.to_string_lossy();
            if name.contains(reader_match) {
                let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)?;
                info!("connected to reader: {}", name);
                return Ok(Self {
                    card,
                    recv_buf: vec![0u8; 1024],
                });
            }
        }

        Err(KeycardError::NoReader)
    }

    /// List all available readers (without connecting).
    pub fn list_readers() -> Result<Vec<String>> {
        let ctx = Context::establish(Scope::System)?;

        let mut readers_buf = vec![0u8; 4096];
        let readers: Vec<String> = ctx
            .list_readers(&mut readers_buf)?
            .map(|r| r.to_string_lossy().into_owned())
            .collect();

        Ok(readers)
    }

    /// Send a raw APDU and return the full response (including SW).
    pub fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        debug!("→ {}", hex::encode(apdu));

        let response = self
            .card
            .transmit(apdu, &mut self.recv_buf)
            .map_err(|e| KeycardError::CardComm(e.to_string()))?;

        let result = response.to_vec();
        debug!(
            "← {} (SW={:04X})",
            hex::encode(&result),
            apdu::parse_sw(&result)
        );

        Ok(result)
    }

    /// Send an APDU and check that SW=9000. Returns response data only.
    pub fn transmit_ok(&mut self, apdu_bytes: &[u8]) -> Result<Vec<u8>> {
        let response = self.transmit(apdu_bytes)?;
        let sw = apdu::parse_sw(&response);

        if sw != apdu::SW_OK {
            return Err(KeycardError::Apdu { sw });
        }

        Ok(apdu::response_data(&response).to_vec())
    }

    /// SELECT the Keycard applet and parse the response.
    pub fn select_keycard(&mut self) -> Result<ApplicationInfo> {
        let cmd = apdu::select_keycard();
        let data = self.transmit_ok(&cmd)?;

        parse_application_info(&data)
    }
}

/// Bits of the applet's status byte (tag `8C`): `0x10` initialized, `0x20`
/// LEE mode (a master key is loaded), low nibble the PIN attempts left.
///
/// The nibble has to be masked rather than taken as "everything that is not
/// `0x10`", or a LEE-mode card reports 32-odd retries.
const APP_STATUS_INITIALIZED: u8 = 0x10;
const APP_STATUS_LEE_MODE: u8 = 0x20;
const APP_STATUS_PIN_RETRIES: u8 = 0x0F;

/// Read a BER-TLV length field; returns `(value_len, header_len_after_tag)`.
fn ber_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 3 || data.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Parse the SELECT response into [`ApplicationInfo`].
///
/// Public because the state it reports — blank card versus initialized one
/// — decides what a provisioning flow may do next, and [`Transport`] is
/// PC/SC only, so nothing driving the simulator could ask it.
///
/// **Three shapes, not two**, and the third is why this function is longer
/// than it looks:
///
/// - **Stock, uninitialized:** a bare `80 <len> <ecc pub>` — the
///   secure-channel public key and nothing else.
/// - **Stock, initialized:** `A4 <len> { 8F uid, 80 pubkey, 02 version, … }`.
///   Stock sends this template *only* after INIT, so the tag alone meant
///   initialized.
/// - **Secure Channel V2, either way:** `A4 <len> { 02 version, 8C status,
///   8E key-uid, 8D capabilities, 8A certificate }`. V2 authenticates from
///   the certificate, so there is no `80` key and no `8F` UID — and the
///   template is sent whether or not the card has been INIT'd, with the
///   answer in the `8C` status byte.
///
///   **This is upstream's format, not our fork's.** Keycard master emits the
///   same layout, and neither `80` nor `8F` is coming back, so the
///   certificate is the primary path and the stock tags above are the
///   fallback — kept for V1 cards such as the Cryptnox, not for the cards
///   this crate is being written for.
///
/// Both fork differences are easy to make fatal. Treating a missing `80`
/// as `NotKeycard` would make every real Kenter card read as "not a Kenter
/// card" — including in `kenter-ui`'s first-run reader check, which goes
/// through here. And inferring `initialized` from the `A4` tag would report
/// a blank forked card as ready to use, so first run would offer to unlock
/// a card that has no PIN.
pub fn parse_application_info(data: &[u8]) -> Result<ApplicationInfo> {
    if data.len() < 2 {
        return Err(KeycardError::NotKeycard);
    }

    match data[0] {
        // Uninitialized applet: bare secure-channel public key under tag 0x80.
        0x80 => {
            let len = data[1] as usize;
            let pk = data
                .get(2..2 + len)
                .ok_or(KeycardError::NotKeycard)?
                .to_vec();
            if pk.is_empty() {
                return Err(KeycardError::NotKeycard);
            }
            debug!("uninitialized card: SC pubkey only ({} bytes)", pk.len());
            Ok(ApplicationInfo {
                initialized: false,
                instance_uid: Vec::new(),
                secure_channel_public_key: pk,
                app_version: (0, 0),
                remaining_pairing_slots: 0,
                key_initialized: false,
                pin_retries: None,
            })
        }
        // Initialized applet: Application Info Template with nested TLVs.
        0xA4 => {
            // Length may be BER long-form (e.g. `81 81` once a key UID is present
            // and the template exceeds 127 bytes).
            let (len, hdr) = ber_length(&data[1..]).ok_or(KeycardError::NotKeycard)?;
            let payload = data
                .get(1 + hdr..1 + hdr + len)
                .ok_or(KeycardError::NotKeycard)?;

            let mut offset = 0;
            let mut instance_uid = Vec::new();
            let mut sc_pub_key = Vec::new();
            let mut app_version = (0u8, 0u8);
            let mut remaining_slots = 0u8;
            let mut key_initialized = false;
            // Fork-only. `8C` is the status byte and `8A` the identity
            // certificate, which together replace stock's `8F` UID and `80`
            // public key — Secure Channel V2 authenticates from the cert, so
            // there is no bare key to send.
            let mut status: Option<u8> = None;
            let mut cert: &[u8] = &[];

            while offset + 2 <= payload.len() {
                let tag = payload[offset];
                let vlen = payload[offset + 1] as usize;
                offset += 2;
                let Some(value) = payload.get(offset..offset + vlen) else {
                    break;
                };
                offset += vlen;

                match tag {
                    0x8F => instance_uid = value.to_vec(), // Instance UID
                    0x80 => sc_pub_key = value.to_vec(),   // SC public key
                    0x02 if value.len() >= 2 => app_version = (value[0], value[1]),
                    0x01 if !value.is_empty() => remaining_slots = value[0],
                    0x8E => key_initialized = !value.is_empty(), // Key UID present ⇒ a key exists
                    0x8C if !value.is_empty() => status = Some(value[0]),
                    0x8A => cert = value,
                    _ => debug!("unknown TLV tag {:#04x}, len={}", tag, vlen),
                }
            }

            // The fork leads its certificate with the 33-byte compressed
            // identity key, which is the nearest thing it has to stock's
            // `80`. Taking it here means callers that only want "is this a
            // Keycard" need not know which applet answered.
            if sc_pub_key.is_empty() && cert.len() >= 33 {
                sc_pub_key = cert[..33].to_vec();
            }
            if sc_pub_key.is_empty() {
                return Err(KeycardError::NotKeycard);
            }

            // **Not `true`.** Stock sends the Application Info Template only
            // once INIT has run, so the tag alone meant initialized. The fork
            // sends it either way and puts the answer in the status byte, so
            // assuming from the tag reported every blank forked card as
            // ready to use — and first run would have offered to unlock a
            // card with no PIN set.
            let initialized = match status {
                Some(st) => st & APP_STATUS_INITIALIZED != 0,
                None => true,
            };
            // Stock says "a key exists" with a non-empty key UID; the fork
            // also sets the LEE bit when its master is loaded. Either will
            // do, and taking both means this does not depend on which
            // applet answered.
            key_initialized |= status.is_some_and(|st| st & APP_STATUS_LEE_MODE != 0);
            Ok(ApplicationInfo {
                initialized,
                instance_uid,
                secure_channel_public_key: sc_pub_key,
                app_version,
                remaining_pairing_slots: remaining_slots,
                key_initialized,
                // Only once there is a PIN to have attempts at. Before
                // INIT the whole status byte is zero, and `Some(0)` there
                // reads as "blocked, no attempts left" — the opposite of a
                // blank card's position.
                pin_retries: status
                    .filter(|_| initialized)
                    .map(|st| st & APP_STATUS_PIN_RETRIES),
            })
        }
        _ => Err(KeycardError::NotKeycard),
    }
}
