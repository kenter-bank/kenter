/// Keycard applet AID
pub const KEYCARD_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01];

/// APDU instruction bytes
pub const INS_SELECT: u8 = 0xA4;
pub const INS_INIT: u8 = 0xFE;
pub const INS_OPEN_SECURE_CHANNEL: u8 = 0x10;
pub const INS_MUTUALLY_AUTHENTICATE: u8 = 0x11;
pub const INS_PAIR: u8 = 0x12;
pub const INS_UNPAIR: u8 = 0x13;
pub const INS_GET_STATUS: u8 = 0xF2;
pub const INS_VERIFY_PIN: u8 = 0x20;
pub const INS_CHANGE_PIN: u8 = 0x21;
pub const INS_UNBLOCK_PIN: u8 = 0x22;
pub const INS_GENERATE_KEY: u8 = 0xD4;
pub const INS_SIGN: u8 = 0xC0;
pub const INS_DERIVE_KEY: u8 = 0xD1;
pub const INS_EXPORT_KEY: u8 = 0xC2;
pub const INS_LOAD_KEY: u8 = 0xD0;
pub const INS_REMOVE_KEY: u8 = 0xD3;
pub const INS_STORE_DATA: u8 = 0xE2;
pub const INS_GET_DATA: u8 = 0xCA;
pub const INS_IDENTIFY: u8 = 0x14;

/// CLA byte for Keycard commands
pub const CLA_GP: u8 = 0x80;

/// Status words
pub const SW_OK: u16 = 0x9000;
pub const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
pub const SW_AUTHENTICATION_BLOCKED: u16 = 0x6983;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_WRONG_P1P2: u16 = 0x6A86;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;
pub const SW_REFERENCED_DATA_NOT_FOUND: u16 = 0x6A88;

/// GET STATUS P1 values
pub const STATUS_P1_APP: u8 = 0x00;
pub const STATUS_P1_KEY_PATH: u8 = 0x01;

/// STORE DATA tags for our custom slot storage
pub const STORE_TAG_STELLAR_VAULT: u8 = 0x01;

/// Build a SELECT APDU for the Keycard applet.
pub fn select_keycard() -> Vec<u8> {
    let mut apdu = vec![0x00, INS_SELECT, 0x04, 0x00, KEYCARD_AID.len() as u8];
    apdu.extend_from_slice(KEYCARD_AID);
    apdu
}

/// Build a GET STATUS APDU.
pub fn get_status(p1: u8) -> Vec<u8> {
    vec![CLA_GP, INS_GET_STATUS, p1, 0x00, 0x00]
}

/// Build a PAIR (first step) APDU.
/// p1=0x00 for first step (send client salt + hash)
pub fn pair_step1(client_data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_GP, INS_PAIR, 0x00, 0x00, client_data.len() as u8];
    apdu.extend_from_slice(client_data);
    apdu
}

/// Build a PAIR (second step) APDU.
/// p1=0x01 for second step (send client certificate)
pub fn pair_step2(client_certificate: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_GP, INS_PAIR, 0x01, 0x00, client_certificate.len() as u8];
    apdu.extend_from_slice(client_certificate);
    apdu
}

/// Build an OPEN SECURE CHANNEL APDU.
/// Sends the host's ephemeral secp256k1 public key (65 bytes, uncompressed).
pub fn open_secure_channel(pairing_index: u8, host_public_key: &[u8]) -> Vec<u8> {
    let mut apdu = vec![
        CLA_GP,
        INS_OPEN_SECURE_CHANNEL,
        pairing_index,
        0x00,
        host_public_key.len() as u8,
    ];
    apdu.extend_from_slice(host_public_key);
    apdu
}

/// Build a MUTUALLY AUTHENTICATE APDU.
pub fn mutually_authenticate(data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![
        CLA_GP,
        INS_MUTUALLY_AUTHENTICATE,
        0x00,
        0x00,
        data.len() as u8,
    ];
    apdu.extend_from_slice(data);
    apdu
}

/// Build a VERIFY PIN APDU (plaintext, before secure channel wrapping).
pub fn verify_pin(pin: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_GP, INS_VERIFY_PIN, 0x00, 0x00, pin.len() as u8];
    apdu.extend_from_slice(pin);
    apdu
}

/// Build a GENERATE KEY APDU (creates new secp256k1 master key on card).
pub fn generate_key() -> Vec<u8> {
    vec![CLA_GP, INS_GENERATE_KEY, 0x00, 0x00, 0x00]
}

/// Build a SIGN APDU for a 32-byte hash.
pub fn sign(hash: &[u8; 32]) -> Vec<u8> {
    let mut apdu = vec![CLA_GP, INS_SIGN, 0x00, 0x00, 0x20];
    apdu.extend_from_slice(hash);
    apdu
}

/// Build a STORE DATA APDU.
pub fn store_data(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = vec![CLA_GP, INS_STORE_DATA, tag, 0x00, data.len() as u8];
    apdu.extend_from_slice(data);
    apdu
}

/// Build a GET DATA APDU.
pub fn get_data(tag: u8) -> Vec<u8> {
    vec![CLA_GP, INS_GET_DATA, tag, 0x00, 0x00]
}

/// Build an INIT APDU (first-time card setup).
/// Data: PIN(6) || PUK(12) || pairing_secret(32)
pub fn init(pin: &[u8], puk: &[u8], pairing_secret: &[u8; 32]) -> Vec<u8> {
    let total_len = pin.len() + puk.len() + pairing_secret.len();
    let mut apdu = vec![CLA_GP, INS_INIT, 0x00, 0x00, total_len as u8];
    apdu.extend_from_slice(pin);
    apdu.extend_from_slice(puk);
    apdu.extend_from_slice(pairing_secret);
    apdu
}

/// Parse status word from the last 2 bytes of a response.
pub fn parse_sw(response: &[u8]) -> u16 {
    if response.len() < 2 {
        return 0;
    }
    let sw1 = response[response.len() - 2] as u16;
    let sw2 = response[response.len() - 1] as u16;
    (sw1 << 8) | sw2
}

/// Extract response data (everything before the 2-byte status word).
pub fn response_data(response: &[u8]) -> &[u8] {
    if response.len() < 2 {
        return &[];
    }
    &response[..response.len() - 2]
}
