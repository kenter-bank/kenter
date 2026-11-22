//! A backup on paper: the wallet and each note as separate, independent
//! items.
//!
//! # Sealed under the seed
//!
//! A paper code is sealed under **the seed**, the same key the `.kbk` uses,
//! not under its own memorised passphrase. A sheet with its own passphrase
//! would make recovery need a third secret in exactly the situation where
//! things have been lost.
//!
//! That makes this a *backup* and not cash. A paper bearer note — the raw
//! container, spendable by whoever photographs it — is a different artefact,
//! and nothing here produces one.
//!
//! # Why items, and not one big blob
//!
//! Putting the whole `.kbk` on paper, cut into symbols, has one bad
//! property that outweighs everything else: the payload is a single
//! compressed, sealed blob, so **one unreadable symbol loses the entire
//! backup**. A coffee ring on page three of four takes the other three with
//! it.
//!
//! So each note is its own sealed item with its own symbols, and the
//! wallet's own state — the owner-index counter and any pending receives —
//! is one more. Damage is contained to what it touches: lose a sheet, lose
//! those notes, keep the rest. It also makes printing incremental, since a
//! new note is a new sheet rather than a reprint.
//!
//! It is *also* smaller. A `.kbk` is JSON carrying hex, four bits of
//! entropy per byte; sealing each note's bytes directly drops that
//! doubling, and a four-note wallet goes from fourteen symbols to about
//! nine.
//!
//! # Error correction
//!
//! Level **M** (~15% recovery), not H.
//!
//! H is the obvious choice: the threats to paper are folding, fading and
//! coffee, and within an item the chunks have no redundancy between them,
//! so per-symbol damage tolerance is what keeps an item readable. But the
//! 30% H spends on recovery has to come out of the same symbol: it drives
//! a sheet symbol to QR version 31, and at that density a camera reads back
//! only the wallet item, the one small enough to land at a low version.
//!
//! **A symbol too dense to read undamaged gains nothing from tolerating
//! damage.** At M the same bytes sit at version 22, which reads, and the
//! item still needs every one of its symbols — so the alternative,
//! splitting further at H, would give each item *more* ways to fail while
//! costing two to three times the paper.
//!
//! The level is not part of the format. A reader decodes any level without
//! being told, so sheets printed at H stay readable.
//!
//! # What a symbol carries
//!
//! ```text
//! "KPB2" | wallet [u8;8] | kind u8 | item u16 | items u16 | index u16 | total u16
//!        | digest u32 | payload
//! ```
//!
//! `wallet` is the seed fingerprint, the same value the `.kbk` header
//! carries. It is here so a sheet can say **which wallet it belongs to
//! before anything is decrypted** — without it the only symptom of
//! scanning the wrong backup is every item failing to open, which reads
//! like a damaged sheet rather than the wrong one. It is printed on the
//! page in clear already, so it leaks nothing new.
//!
//! `digest` is of the whole item and repeated in each of its chunks, so
//! symbols from two different sheets cannot be combined.
//!
//! `items` is how many items the whole backup has, and it is in the
//! **cleartext** header because without it, a note whose
//! every symbol is missing is not missing, it is *invisible*. A holder who
//! loses one sheet would scan the rest, be told four notes came back when
//! there were five, and never learn otherwise. Keeping the count where it
//! can be read without a key means a scan can say "note 3 is missing
//! entirely" instead of silently returning less. It reveals only how many
//! notes a backup holds, which the labels printed beside the symbols
//! already show.

use crate::error::{Result, WalletError};
use crate::models::{HeldToken, PendingReceive};

/// `KPB2` — Kenter Paper Backup, one sealed item per note (see the module
/// note on why not one blob).
const MAGIC: &[u8; 4] = b"KPB2";
const HEADER: usize = 4 + FINGERPRINT + 1 + 2 + 2 + 2 + 2 + 4;

/// The seed fingerprint is sixteen hex characters; carried as the eight
/// bytes they encode.
const FINGERPRINT: usize = 8;

/// Hex fingerprint to bytes, padded or truncated to [`FINGERPRINT`].
fn fingerprint_bytes(hex: &str) -> [u8; FINGERPRINT] {
    let mut out = [0u8; FINGERPRINT];
    let decoded = hex::decode(hex).unwrap_or_default();
    let n = decoded.len().min(FINGERPRINT);
    out[..n].copy_from_slice(&decoded[..n]);
    out
}

/// Byte capacity of a version-40 symbol at the level a sheet renders,
/// error correction **M**.
///
/// At **H** it would be 1273. See [`DEFAULT_CHUNK_PAYLOAD`] for the
/// measurement; the short version is that H spends 30% of every symbol on
/// recovery, that spend drives a sheet symbol to version 31, and a symbol
/// too dense to read undamaged does not benefit from being able to survive
/// damage.
pub const SYMBOL_CAPACITY: usize = 2331;

/// Payload bytes per symbol, after the header, if a symbol is filled to the
/// version-40 ceiling.
///
/// This is the *format's* limit, not the one we print to. See
/// [`chunk_payload`].
pub const CHUNK_PAYLOAD: usize = SYMBOL_CAPACITY - HEADER;

/// Payload bytes a symbol is actually filled to.
///
/// # Why a cap is needed even at M
///
/// Error correction M (see the module note) is what keeps a sheet symbol
/// at a version a camera reads, without costing a single page. It does not
/// remove the need for a ceiling.
///
/// At M a version-40 symbol holds 2331 bytes, so an item under that
/// becomes **one** symbol at whatever version it happens to need — and a
/// three-pair note, 1151 bytes sealed, would land on a single version-27
/// symbol. 27 is inside the band that did not read. The cap is what stops an
/// item quietly becoming one symbol too dense to read.
///
/// A function rather than a constant, and overridable, for the same reason
/// the module size is: this is a claim about printers and cameras, and it
/// should be settled by printing one and scanning it.
///
/// ```text
/// KENTER_PAPER_CHUNK_PAYLOAD=600 cargo run -p kenter-ui --example paper_sweep
/// ```
///
/// Clamped, so a typo cannot quietly produce a sheet nothing can read, and
/// never above the ceiling the format allows.
pub fn chunk_payload() -> usize {
    std::env::var("KENTER_PAPER_CHUNK_PAYLOAD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| (100..=CHUNK_PAYLOAD).contains(n))
        .unwrap_or(DEFAULT_CHUNK_PAYLOAD)
}

/// What [`chunk_payload`] returns unless overridden.
///
/// **850 bytes**, which at error correction M is version 23 or below for
/// every item size a wallet produces.
///
/// # Where the number comes from
///
/// `examples/calibration_sheet` prints nine symbols from 1248 bytes down
/// to 212. Read back through `examples/paper_lab`:
///
/// | payload | version | alignment grid | read |
/// |---|---|---|---|
/// | 1248 | 40 | 7x7 | no |
/// | 636 | 29 | 6x6 | no |
/// | 530 | 26 | 5x5 | yes |
/// | 477 | 24 | 5x5 | no |
/// | 424 | 23 | 5x5 | yes |
/// | 371 | 21 | 5x5 | yes |
/// | 318 | 20 | 4x4 | yes |
/// | 265 | 18 | 4x4 | yes |
/// | 212 | 16 | 4x4 | yes |
///
/// Those payloads were measured at **H**, so read the version column, not
/// the byte column: the boundary is where the alignment grid thickens past
/// 5x5. Everything at version 26 and below read; the two symbols above it
/// did not. 477 at version 24 is the one inversion, a single sample, and
/// worth re-shooting.
///
/// Targeting version 23 for margin, at M that is 850 bytes. A four-pair
/// note seals to about 1441 and comes out as two symbols of 721 — version
/// 22, the same symbol count the H layout needed, so M costs no paper.
///
/// # What this number is not
///
/// It was measured **off a phone screen**, not paper: the sheet displayed
/// on a phone and read with a webcam. A screen adds moire, backlight and
/// its own pixel pitch, so this is a **floor** — paper should tolerate
/// more.
///
/// Measured at M with a ladder that goes above the cap as well as below:
/// **version 30 reads and version 35 does not**, clean and monotonic. So
/// the cap at version 24 has more margin than it needs. 1087 bytes,
/// version 27, is the number to reach for if page counts matter more. It
/// is left unspent because the gain is one page at around eight notes of
/// eight pairs, and this is the artifact whose failure is silent and years
/// late.
///
/// It also does not explain everything. `examples/camera_probe` puts that
/// camera at 6.62 px/module on a version-40 symbol filling the frame,
/// which should read and does not. The screen is the likeliest reason; it
/// is not proven.
pub const DEFAULT_CHUNK_PAYLOAD: usize = 850;

/// What one item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The wallet's own state: the owner-index counter and pending
    /// receives. Small, and worth its own item because losing it is not
    /// the same as losing a note — it costs the standing pay tag and risks
    /// reissuing an index, rather than costing money.
    Wallet,
    /// One note.
    Note,
}

impl Kind {
    fn tag(self) -> u8 {
        match self {
            Kind::Wallet => 0,
            Kind::Note => 1,
        }
    }
    fn from_tag(t: u8) -> Option<Self> {
        match t {
            0 => Some(Kind::Wallet),
            1 => Some(Kind::Note),
            _ => None,
        }
    }
    /// What to print under the symbol.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Wallet => "wallet",
            Kind::Note => "note",
        }
    }
}

/// One symbol's worth of bytes, ready to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Which wallet this belongs to, as the page prints it.
    pub wallet: String,
    pub kind: Kind,
    /// Which item within this backup, 0-based.
    pub item: u16,
    /// How many items the whole backup has. See the module note.
    pub items: u16,
    /// Which symbol within the item, 0-based.
    pub index: u16,
    /// Symbols in this item.
    pub total: u16,
    pub bytes: Vec<u8>,
}

impl Chunk {
    /// What goes under the symbol on the page.
    ///
    /// Names the item, not just the symbol, because the thing a holder
    /// needs to see is which *note* is incomplete.
    pub fn label(&self) -> String {
        match self.kind {
            Kind::Wallet => format!("wallet {}/{}", self.index + 1, self.total),
            Kind::Note => format!(
                "note {} \u{b7} {}/{}",
                self.item,
                self.index + 1,
                self.total
            ),
        }
    }
}

/// CRC-32 (IEEE). Tells two sheets apart and catches a reassembly that
/// produced nonsense; not a security property, since the payload is sealed
/// and authenticated underneath.
fn digest(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.at + n > self.b.len() {
            return Err(WalletError::Backup("the item is truncated".into()));
        }
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(s.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn arr32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
}

/// A note as bytes.
///
/// Binary rather than JSON, and this is where the page count went: the
/// `.kbk` stores every blob as hex inside JSON, which doubles the one field
/// that dominates a note's size. Writing the bytes as bytes gets that back.
fn write_note(t: &HeldToken) -> Vec<u8> {
    let mut out = Vec::with_capacity(t.blob.len() + 160);
    out.extend_from_slice(&t.ephemeral_public_key);
    out.extend_from_slice(&t.event_id);
    put_u64(&mut out, t.amount);
    put_u64(&mut out, t.imported_at as u64);
    put_bytes(&mut out, &t.blob);
    put_bytes(&mut out, t.label.as_deref().unwrap_or("").as_bytes());
    match t.owner_index {
        Some(i) => {
            out.push(1);
            put_u32(&mut out, i);
        }
        None => out.push(0),
    }
    match t.owner_commitment {
        Some(c) => {
            out.push(1);
            out.extend_from_slice(&c);
        }
        None => out.push(0),
    }
    out.push(u8::from(t.spent_away) | (u8::from(t.marked_spent) << 1));
    put_u32(&mut out, t.exports.backup);
    put_u32(&mut out, t.exports.to_card);
    put_u32(&mut out, t.exports.handover);
    out
}

fn read_note(b: &[u8]) -> Result<HeldToken> {
    let mut r = Reader { b, at: 0 };
    let ephemeral_public_key = r.arr32()?;
    let event_id = r.arr32()?;
    let amount = r.u64()?;
    let imported_at = r.u64()? as i64;
    let blob = r.bytes()?;
    let label = String::from_utf8(r.bytes()?)
        .map_err(|_| WalletError::Backup("the note's label is not text".into()))?;
    let owner_index = if r.u8()? == 1 { Some(r.u32()?) } else { None };
    let owner_commitment = if r.u8()? == 1 { Some(r.arr32()?) } else { None };
    let flags = r.u8()?;
    let exports = crate::models::ExportLog {
        backup: r.u32()?,
        to_card: r.u32()?,
        handover: r.u32()?,
    };

    // The id is derived from the container, never carried: a stored id that
    // disagrees with its own blob is the forgery `backup::check` exists to
    // catch, and paper should not reintroduce the field it checks.
    let bearer = kenter_crypto::container::deserialize_bearer_token(&blob)
        .map_err(|e| WalletError::Backup(format!("the note does not parse: {e}")))?;

    Ok(HeldToken {
        id: crate::models::note_id(&bearer.ephemeral_address(), bearer.slot_id),
        slot_id: bearer.slot_id,
        ephemeral_public_key,
        event_id,
        amount,
        blob,
        imported_at,
        // Paper carries no mint, and restoring from paper is not a
        // ledger confirming anything. It binds on its next Active read.
        mint: None,
        label: (!label.is_empty()).then_some(label),
        owner_index,
        owner_commitment,
        spent_away: flags & 1 != 0,
        exports,
        marked_spent: flags & 2 != 0,
    })
}

fn write_wallet(next_owner_index: Option<u32>, pending: &[PendingReceive]) -> Vec<u8> {
    let mut out = Vec::new();
    match next_owner_index {
        Some(i) => {
            out.push(1);
            put_u32(&mut out, i);
        }
        None => out.push(0),
    }
    put_u16(&mut out, pending.len() as u16);
    for p in pending {
        put_u32(&mut out, p.index);
        out.extend_from_slice(&p.commitment);
        put_u64(&mut out, p.created_at as u64);
    }
    out
}

fn read_wallet(b: &[u8]) -> Result<(Option<u32>, Vec<PendingReceive>)> {
    let mut r = Reader { b, at: 0 };
    let next = if r.u8()? == 1 { Some(r.u32()?) } else { None };
    let n = r.u16()?;
    let mut pending = Vec::with_capacity(n as usize);
    for _ in 0..n {
        pending.push(PendingReceive {
            index: r.u32()?,
            commitment: r.arr32()?,
            created_at: r.u64()? as i64,
        });
    }
    Ok((next, pending))
}

/// Cut one item's bytes into symbols.
fn chunk(wallet: &str, kind: Kind, item: u16, items: u16, body: &[u8]) -> Result<Vec<Chunk>> {
    let packed = miniz_oxide::deflate::compress_to_vec(body, 9);
    let sum = digest(&packed);
    // Balanced, not filled-then-overflowed. Packing each symbol to the
    // version-40 ceiling and leaving the remainder in the last one makes
    // the FIRST symbol of every multi-symbol item the densest thing on
    // the page and the last one nearly empty -- 1273 bytes beside 127.
    // An item needs every one of its symbols, so its readability is set
    // by its worst, and that arrangement maximises exactly that.
    //
    // Splitting evenly costs nothing: same symbol count, same bytes,
    // but a two-symbol item becomes ~700 and ~700, both at a much lower
    // QR version with correspondingly fatter modules. Found on paper --
    // the short second symbols of a real backup read while the dense
    // first ones would not, at any distance.
    let want = packed.len().div_ceil(chunk_payload()).max(1);
    let per = packed.len().div_ceil(want).max(1);
    let parts: Vec<&[u8]> = packed.chunks(per).collect();
    let total = u16::try_from(parts.len())
        .map_err(|_| WalletError::Backup("that item needs more symbols than paper can hold".into()))?;

    Ok(parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let index = i as u16;
            let mut bytes = Vec::with_capacity(HEADER + part.len());
            bytes.extend_from_slice(MAGIC);
            bytes.extend_from_slice(&fingerprint_bytes(wallet));
            bytes.push(kind.tag());
            put_u16(&mut bytes, item);
            put_u16(&mut bytes, items);
            put_u16(&mut bytes, index);
            put_u16(&mut bytes, total);
            put_u32(&mut bytes, sum);
            bytes.extend_from_slice(part);
            Chunk { wallet: wallet.to_string(), kind, item, items, index, total, bytes }
        })
        .collect())
}

/// One self-contained symbol carrying exactly `payload`, for measuring
/// what a camera or a scanner can actually read.
///
/// Real chunks are packed to [`CHUNK_PAYLOAD`], which fixes them at the
/// densest QR version there is. A calibration sheet needs symbols of
/// chosen sizes instead, and they must carry a **valid header** -- a
/// sheet of well-formed QR codes containing nonsense would measure the
/// decoder and tell us nothing about whether a symbol is ours.
///
/// `payload` is carried verbatim: no compression, so the size asked for
/// is the size printed.
pub fn calibration_symbol(wallet: &str, item: u16, items: u16, payload: &[u8]) -> Chunk {
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&fingerprint_bytes(wallet));
    bytes.push(Kind::Note.tag());
    put_u16(&mut bytes, item);
    put_u16(&mut bytes, items);
    put_u16(&mut bytes, 0);
    put_u16(&mut bytes, 1);
    put_u32(&mut bytes, digest(payload));
    bytes.extend_from_slice(payload);
    Chunk {
        wallet: wallet.to_string(),
        kind: Kind::Note,
        item,
        items,
        index: 0,
        total: 1,
        bytes,
    }
}

/// Everything a backup puts on paper, as independent items.
///
/// `seal` turns one item's plaintext into its sealed bytes — the caller
/// supplies it so this module never holds a key.
pub fn encode<F>(
    wallet: &str,
    tokens: &[HeldToken],
    pending: &[PendingReceive],
    next_owner_index: Option<u32>,
    mut seal: F,
) -> Result<Vec<Chunk>>
where
    F: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let items = u16::try_from(tokens.len() + 1)
        .map_err(|_| WalletError::Backup("too many notes for one paper backup".into()))?;
    let mut out = chunk(
        wallet,
        Kind::Wallet,
        0,
        items,
        &seal(&write_wallet(next_owner_index, pending))?,
    )?;
    for (i, t) in tokens.iter().enumerate() {
        out.extend(chunk(
            wallet,
            Kind::Note,
            (i + 1) as u16,
            items,
            &seal(&write_note(t))?,
        )?);
    }
    Ok(out)
}

/// A symbol read back off paper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    /// Which wallet the symbol says it belongs to.
    pub wallet: String,
    pub kind: Kind,
    pub item: u16,
    pub items: u16,
    pub index: u16,
    pub total: u16,
    sum: u32,
    payload: Vec<u8>,
}

/// Read one symbol's bytes.
pub fn read_symbol(bytes: &[u8]) -> Result<Scanned> {
    if bytes.len() < HEADER || &bytes[..4] != MAGIC {
        return Err(WalletError::Backup(
            "that is not part of a Kenter paper backup".into(),
        ));
    }
    let wallet = hex::encode(&bytes[4..4 + FINGERPRINT]);
    let b = &bytes[4 + FINGERPRINT..];
    let kind = Kind::from_tag(b[0])
        .ok_or_else(|| WalletError::Backup("that symbol is of a kind this build does not know".into()))?;
    let item = u16::from_be_bytes([b[1], b[2]]);
    let items = u16::from_be_bytes([b[3], b[4]]);
    let index = u16::from_be_bytes([b[5], b[6]]);
    let total = u16::from_be_bytes([b[7], b[8]]);
    let sum = u32::from_be_bytes([b[9], b[10], b[11], b[12]]);
    if total == 0 || index >= total {
        return Err(WalletError::Backup(format!(
            "that symbol says it is {} of {total}, which cannot be right",
            index as u32 + 1
        )));
    }
    if items == 0 || item >= items {
        return Err(WalletError::Backup(format!(
            "that symbol says it is item {item} of {items}, which cannot be right"
        )));
    }
    Ok(Scanned { wallet, kind, item, items, index, total, sum, payload: bytes[HEADER..].to_vec() })
}

/// How far a scan has got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// Items that have every symbol.
    pub complete: Vec<u16>,
    /// Items still missing symbols, as `(item, missing 1-based)`.
    pub partial: Vec<(u16, Vec<u16>)>,
    /// Items not seen at all \u2014 a whole sheet lost, rather than a symbol.
    ///
    /// Knowable only because the item count travels in the cleartext
    /// header. Without it a lost sheet is not missing, it is invisible,
    /// and a holder would be handed four notes where there were five.
    pub absent: Vec<u16>,
    /// Whether the wallet item is complete.
    pub wallet: bool,
}

impl Progress {
    /// Anything at all can be recovered.
    pub fn has_anything(&self) -> bool {
        !self.complete.is_empty()
    }

    /// Every item is complete.
    pub fn is_complete(&self) -> bool {
        self.partial.is_empty() && self.absent.is_empty() && self.wallet
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        let notes = self.complete.iter().filter(|i| **i > 0).count();
        if notes > 0 {
            parts.push(format!("{notes} note{} readable", if notes == 1 { "" } else { "s" }));
        }
        if self.wallet {
            parts.push("wallet record readable".into());
        }
        for (item, missing) in &self.partial {
            let list: Vec<String> = missing.iter().map(|m| m.to_string()).collect();
            let what = if *item == 0 {
                "wallet".to_string()
            } else {
                format!("note {item}")
            };
            parts.push(format!("{what} needs symbol {}", list.join(", ")));
        }
        if !self.absent.is_empty() {
            let list: Vec<String> = self
                .absent
                .iter()
                .map(|i| if *i == 0 { "wallet".into() } else { format!("note {i}") })
                .collect();
            parts.push(format!("nothing scanned for {}", list.join(", ")));
        }
        if parts.is_empty() {
            return "nothing scanned yet".into();
        }
        parts.join("; ")
    }
}

/// Symbols collected so far, in any order and with duplicates.
#[derive(Debug, Clone, Default)]
pub struct Sheet {
    items: std::collections::BTreeMap<u16, Item>,
    /// How many items the backup has, from the first symbol scanned.
    expected: Option<u16>,
    wallet: Option<String>,
}

#[derive(Debug, Clone)]
struct Item {
    kind: Kind,
    total: u16,
    sum: u32,
    parts: std::collections::BTreeMap<u16, Vec<u8>>,
}

impl Sheet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol. Idempotent, because a camera reads the same one many
    /// times a second.
    pub fn add(&mut self, s: Scanned) -> Result<()> {
        // Before anything else, and before any key: the wrong backup must
        // be named as the wrong backup rather than discovered later as a
        // sheet where nothing decrypts.
        match &self.wallet {
            None => self.wallet = Some(s.wallet.clone()),
            Some(known) if *known != s.wallet => {
                return Err(WalletError::Backup(format!(
                    "that symbol belongs to a different wallet ({}), not this sheet\'s ({known})",
                    s.wallet
                )));
            }
            Some(_) => {}
        }
        match self.expected {
            None => self.expected = Some(s.items),
            Some(n) if n != s.items => {
                return Err(WalletError::Backup(
                    "that symbol is from a backup with a different number of items - \
                     two sheets cannot be mixed"
                        .into(),
                ));
            }
            Some(_) => {}
        }
        let entry = self.items.entry(s.item).or_insert_with(|| Item {
            kind: s.kind,
            total: s.total,
            sum: s.sum,
            parts: Default::default(),
        });
        if entry.sum != s.sum || entry.total != s.total || entry.kind != s.kind {
            return Err(WalletError::Backup(format!(
                "that symbol disagrees with the others for {} {} - two different sheets \
                 cannot be mixed",
                s.kind.label(),
                s.item
            )));
        }
        entry.parts.insert(s.index, s.payload);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Which wallet these symbols are for, once any has been scanned.
    ///
    /// Readable with no key, so a holder can be told they have the wrong
    /// sheet out before being asked for a phrase.
    pub fn wallet(&self) -> Option<&str> {
        self.wallet.as_deref()
    }

    pub fn progress(&self) -> Progress {
        let mut complete = Vec::new();
        let mut partial = Vec::new();
        for (id, item) in &self.items {
            let missing: Vec<u16> = (0..item.total)
                .filter(|i| !item.parts.contains_key(i))
                .map(|i| i + 1)
                .collect();
            if missing.is_empty() {
                complete.push(*id);
            } else {
                partial.push((*id, missing));
            }
        }
        let seen = |i: &u16| self.items.contains_key(i);
        let absent = (0..self.expected.unwrap_or(0)).filter(|i| !seen(i)).collect();
        Progress {
            wallet: complete.contains(&0),
            complete,
            partial,
            absent,
        }
    }

    fn body(item: &Item) -> Result<Vec<u8>> {
        let packed: Vec<u8> = item.parts.values().flatten().copied().collect();
        if digest(&packed) != item.sum {
            return Err(WalletError::Backup(
                "the symbols do not add up - one of them was misread".into(),
            ));
        }
        miniz_oxide::inflate::decompress_to_vec(&packed)
            .map_err(|e| WalletError::Backup(format!("the item is damaged: {e:?}")))
    }

    /// Recover whatever is complete.
    ///
    /// **Partial scans still produce a backup.** That is the whole reason
    /// items exist: three notes out of four is three notes, not nothing,
    /// and a holder who has lost a sheet should get back what survived
    /// rather than an error.
    ///
    /// `open` reverses whatever `seal` did at encode time. A note that will
    /// not open is reported and skipped, so one bad item cannot take the
    /// others with it.
    pub fn finish<F>(&self, mut open: F) -> Result<Recovered>
    where
        F: FnMut(&[u8]) -> Result<Vec<u8>>,
    {
        let mut out = Recovered::default();
        for (id, item) in &self.items {
            if item.parts.len() != item.total as usize {
                continue; // incomplete; `progress` already says so
            }
            let sealed = match Self::body(item) {
                Ok(b) => b,
                Err(e) => {
                    out.failed.push((*id, e.to_string()));
                    continue;
                }
            };
            let plain = match open(&sealed) {
                Ok(p) => p,
                Err(e) => {
                    out.failed.push((*id, e.to_string()));
                    continue;
                }
            };
            match item.kind {
                Kind::Wallet => match read_wallet(&plain) {
                    Ok((next, pending)) => {
                        out.next_owner_index = next;
                        out.pending = pending;
                    }
                    Err(e) => out.failed.push((*id, e.to_string())),
                },
                Kind::Note => match read_note(&plain) {
                    Ok(t) => out.tokens.push(t),
                    Err(e) => out.failed.push((*id, e.to_string())),
                },
            }
        }
        Ok(out)
    }
}

/// What a scan recovered.
#[derive(Debug, Clone, Default)]
pub struct Recovered {
    pub tokens: Vec<HeldToken>,
    pub pending: Vec<PendingReceive>,
    pub next_owner_index: Option<u32>,
    /// Items that were complete but could not be read, as `(item, why)`.
    pub failed: Vec<(u16, String)>,
}

impl Recovered {
    /// As [`crate::backup::BackupContents`], so paper and file restore
    /// through exactly the same code.
    pub fn into_contents(self, created_at: i64) -> crate::backup::BackupContents {
        crate::backup::BackupContents {
            tokens: self.tokens,
            pending: self.pending,
            next_owner_index: self.next_owner_index,
            created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seal and open, standing in for the AEAD. Tagged so a wrong "key"
    /// fails the way a real one would.
    fn seal(b: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0xA7];
        out.extend_from_slice(b);
        Ok(out)
    }
    fn open(b: &[u8]) -> Result<Vec<u8>> {
        match b.split_first() {
            Some((0xA7, rest)) => Ok(rest.to_vec()),
            _ => Err(WalletError::Backup("wrong key".into())),
        }
    }

    const WALLET: &str = "5e1f0c2a9d4b7368";

    /// **An item is only as readable as its worst symbol.**
    ///
    /// Filling each symbol to the ceiling and leaving the remainder in
    /// the last one puts a version-40 symbol beside a nearly empty one.
    /// On paper the short second symbols read from across the room while
    /// the dense first ones do not read at any distance, so the item is
    /// unrecoverable.
    #[test]
    fn an_items_symbols_are_evenly_sized() {
        for len in [
            CHUNK_PAYLOAD + 1,
            CHUNK_PAYLOAD + 100,
            CHUNK_PAYLOAD * 2,
            CHUNK_PAYLOAD * 2 + 7,
            CHUNK_PAYLOAD * 3 + 500,
        ] {
            // Incompressible, so the deflate inside `chunk` cannot
            // shrink this back under one symbol and make the test lie.
            let mut x: u32 = 0x9e37_79b9;
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (x >> 24) as u8
                })
                .collect();

            let chunks = chunk(WALLET, Kind::Note, 0, 1, &body).expect("chunked");
            assert!(chunks.len() > 1, "{len} should need several symbols");

            let sizes: Vec<usize> = chunks.iter().map(|c| c.bytes.len()).collect();
            let biggest = sizes.iter().max().copied().unwrap_or(0);
            let smallest = sizes.iter().min().copied().unwrap_or(0);

            // Even to within one chunk's rounding, never a full symbol
            // beside a stub.
            assert!(
                biggest - smallest <= HEADER + 1,
                "{len} bytes split unevenly: {sizes:?}"
            );
            assert!(
                biggest <= SYMBOL_CAPACITY,
                "{len} bytes made an oversized symbol: {sizes:?}"
            );
        }
    }

    /// Splitting evenly must not cost a symbol, or every backup gets
    /// longer to buy readability it already had.
    #[test]
    fn balancing_uses_no_more_symbols_than_filling_would() {
        for len in [CHUNK_PAYLOAD + 1, CHUNK_PAYLOAD * 2, CHUNK_PAYLOAD * 4 + 3] {
            let body = vec![0u8; len];
            let chunks = chunk(WALLET, Kind::Note, 0, 1, &body).expect("chunked");
            let packed = miniz_oxide::deflate::compress_to_vec(&body, 9);
            assert_eq!(
                chunks.len(),
                packed.len().div_ceil(CHUNK_PAYLOAD).max(1),
                "{len} bytes used more symbols than filling would have"
            );
        }
    }

    fn notes(n: u8) -> Vec<HeldToken> {
        (1..=n)
            .map(|i| crate::testing::spend_note(i, 1_000 + i as u64, i as u32))
            .collect()
    }

    fn pending() -> Vec<PendingReceive> {
        vec![PendingReceive { index: 0, commitment: [0xAB; 32], created_at: 1_700_000_500 }]
    }

    fn scan_all(chunks: &[Chunk]) -> Sheet {
        let mut sheet = Sheet::new();
        for c in chunks {
            sheet.add(read_symbol(&c.bytes).unwrap()).unwrap();
        }
        sheet
    }

    #[test]
    fn every_note_and_the_wallet_survive_the_round_trip() {
        let held = notes(4);
        let chunks = encode(WALLET, &held, &pending(), Some(17), seal).unwrap();
        let out = scan_all(&chunks).finish(open).unwrap();

        assert!(out.failed.is_empty(), "{:?}", out.failed);
        assert_eq!(out.next_owner_index, Some(17));
        assert_eq!(out.pending, pending());

        let mut got = out.tokens;
        got.sort_by(|a, b| a.id.cmp(&b.id));
        let mut want = held;
        want.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(got, want, "every field of every note");
    }

    /// The property the whole redesign is for.
    #[test]
    fn losing_a_sheet_loses_only_what_was_on_it() {
        let held = notes(4);
        let chunks = encode(WALLET, &held, &pending(), Some(17), seal).unwrap();

        // Note 2 is gone entirely; everything else scanned.
        let mut sheet = Sheet::new();
        for c in chunks.iter().filter(|c| c.item != 2) {
            sheet.add(read_symbol(&c.bytes).unwrap()).unwrap();
        }
        let out = sheet.finish(open).unwrap();

        assert_eq!(out.tokens.len(), 3, "three notes out of four is three notes");
        assert_eq!(out.next_owner_index, Some(17), "the wallet record survived");
        assert!(out.failed.is_empty());
    }

    /// A damaged note must not take its neighbours with it.
    #[test]
    fn one_unreadable_note_does_not_lose_the_others() {
        let held = notes(3);
        let mut chunks = encode(WALLET, &held, &pending(), Some(9), seal).unwrap();
        let victim = chunks.iter().position(|c| c.item == 2).unwrap();
        let n = chunks[victim].bytes.len();
        chunks[victim].bytes[n - 1] ^= 0xFF;

        let out = scan_all(&chunks).finish(open).unwrap();
        assert_eq!(out.tokens.len(), 2);
        assert_eq!(out.failed.len(), 1);
        assert_eq!(out.failed[0].0, 2);
    }

    #[test]
    fn an_incomplete_item_is_named_and_the_rest_still_read() {
        let held = notes(3);
        let chunks = encode(WALLET, &held, &pending(), Some(9), seal).unwrap();
        let drop = chunks.iter().find(|c| c.item == 2).unwrap().clone();

        let mut sheet = Sheet::new();
        for c in chunks.iter().filter(|c| !(c.item == 2 && c.index == drop.index)) {
            sheet.add(read_symbol(&c.bytes).unwrap()).unwrap();
        }
        let p = sheet.progress();
        assert!(p.has_anything());
        assert!(!p.is_complete());
        // Either shape of loss is named: a symbol short, or nothing at all.
        let said = p.describe();
        assert!(
            said.contains("note 2 needs symbol") || said.contains("nothing scanned for note 2"),
            "{said}"
        );

        let out = sheet.finish(open).unwrap();
        assert_eq!(out.tokens.len(), 2, "the other two notes still read");
    }

    /// A whole sheet lost must be *visible*. Without the item count in
    /// the clear, a note with no symbols scanned is not missing \u2014 it
    /// simply does not exist, and the holder is handed fewer notes than
    /// they had with nothing to say so.
    #[test]
    fn a_note_with_no_symbols_at_all_is_still_reported_missing() {
        let chunks = encode(WALLET, &notes(4), &pending(), Some(17), seal).unwrap();

        let mut sheet = Sheet::new();
        for c in chunks.iter().filter(|c| c.item != 2) {
            sheet.add(read_symbol(&c.bytes).unwrap()).unwrap();
        }
        let p = sheet.progress();
        assert_eq!(p.absent, vec![2]);
        assert!(!p.is_complete());
        assert!(p.describe().contains("nothing scanned for note 2"), "{}", p.describe());

        // And a complete scan says so.
        let full = scan_all(&chunks).progress();
        assert!(full.is_complete());
        assert!(full.absent.is_empty());
    }

    #[test]
    fn symbols_arrive_in_any_order_and_more_than_once() {
        let held = notes(3);
        let chunks = encode(WALLET, &held, &pending(), Some(9), seal).unwrap();

        let mut sheet = Sheet::new();
        for c in chunks.iter().rev() {
            for _ in 0..3 {
                sheet.add(read_symbol(&c.bytes).unwrap()).unwrap();
            }
        }
        assert_eq!(sheet.finish(open).unwrap().tokens.len(), 3);
    }

    /// The id is derived from the container rather than carried, so paper
    /// cannot reintroduce the mismatch `backup::check` exists to catch.
    #[test]
    fn a_notes_id_comes_from_its_own_bytes() {
        let held = notes(1);
        let chunks = encode(WALLET, &held, &[], None, seal).unwrap();
        let out = scan_all(&chunks).finish(open).unwrap();
        assert_eq!(out.tokens[0].id, held[0].id);
        crate::backup::check(&out.tokens[0]).unwrap();
    }

    #[test]
    fn the_wrong_key_fails_every_item_and_loses_nothing_else() {
        let chunks = encode(WALLET, &notes(2), &[], None, seal).unwrap();
        let out = scan_all(&chunks)
            .finish(|_| Err(WalletError::Backup("wrong key".into())))
            .unwrap();
        assert!(out.tokens.is_empty());
        assert_eq!(out.failed.len(), 3, "two notes and the wallet record");
    }

    /// The wrong backup must be named as the wrong backup, before any key
    /// is involved. Without the fingerprint in the header its only symptom
    /// would be every item failing to decrypt, which reads as a damaged sheet
    /// rather than someone else's.
    #[test]
    fn a_sheet_for_another_wallet_says_so_before_anything_is_decrypted() {
        let mine = encode(WALLET, &notes(1), &[], None, seal).unwrap();
        let theirs = encode("0011223344556677", &notes(1), &[], None, seal).unwrap();

        let mut sheet = Sheet::new();
        sheet.add(read_symbol(&mine[0].bytes).unwrap()).unwrap();
        assert_eq!(sheet.wallet(), Some(WALLET));

        let err = sheet
            .add(read_symbol(&theirs[0].bytes).unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("different wallet"), "{err}");
        assert!(err.contains("0011223344556677"), "{err}");
    }

    /// And a holder can be told which sheet they have out before being
    /// asked for anything.
    #[test]
    fn the_wallet_is_readable_from_one_symbol_with_no_key() {
        let chunks = encode(WALLET, &notes(2), &[], None, seal).unwrap();
        for c in &chunks {
            assert_eq!(c.wallet, WALLET);
            assert_eq!(read_symbol(&c.bytes).unwrap().wallet, WALLET);
        }
    }

    #[test]
    fn symbols_from_two_sheets_cannot_be_mixed() {
        let a = encode(WALLET, &notes(2), &[], Some(1), seal).unwrap();
        let b = encode(WALLET, &notes(3), &[], Some(2), seal).unwrap();

        let mut sheet = Sheet::new();
        sheet.add(read_symbol(&a[0].bytes).unwrap()).unwrap();
        let err = sheet.add(read_symbol(&b[0].bytes).unwrap()).unwrap_err().to_string();
        assert!(err.contains("cannot be mixed"), "{err}");
    }

    #[test]
    fn something_that_is_not_ours_is_named_as_such() {
        assert!(read_symbol(b"https://example.com/nope").unwrap_err().to_string()
            .contains("not part of a Kenter paper backup"));
        assert!(read_symbol(b"KPB2").is_err());
    }

    #[test]
    fn every_symbol_fits_a_version_40_h_symbol() {
        for c in encode(WALLET, &notes(4), &pending(), Some(17), seal).unwrap() {
            assert!(c.bytes.len() <= SYMBOL_CAPACITY, "{} bytes", c.bytes.len());
        }
    }

    /// Items label themselves by what they are, so a holder can see that
    /// note 3 is the one missing rather than "symbol 9".
    #[test]
    fn labels_name_the_item_not_just_the_symbol() {
        let chunks = encode(WALLET, &notes(2), &[], None, seal).unwrap();
        assert!(chunks[0].label().starts_with("wallet "));
        let note = chunks.iter().find(|c| c.kind == Kind::Note).unwrap();
        assert!(note.label().starts_with("note 1"), "{}", note.label());
    }
}
