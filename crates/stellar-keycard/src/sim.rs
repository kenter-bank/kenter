//! `SimTransport` — talks to the applet repo's jcardsim TCP APDU server.
//!
//! Wire protocol (framed, big-endian, one APDU per exchange):
//! ```text
//! client -> server:  u16 length, then <length> APDU command bytes
//! server -> client:  u16 length, then <length> APDU response bytes (data ‖ SW)
//! client -> server:  u16 length = 0   -> resets the card; server replies u16 0
//! ```
//! Start the server (in the applet repo, JDK 11): `gradlew simServer` — it listens
//! on `127.0.0.1:21345`.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::error::{KeycardError, Result};
use crate::transport::CardTransport;

/// Default address the jcardsim `SimServer` listens on.
pub const DEFAULT_SIM_ADDR: &str = "127.0.0.1:21345";

/// A transport over the jcardsim TCP APDU server.
pub struct SimTransport {
    stream: TcpStream,
}

impl SimTransport {
    /// Connect to the simulator server (e.g. [`DEFAULT_SIM_ADDR`]).
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr)
            .map_err(|e| KeycardError::CardComm(format!("sim connect {addr}: {e}")))?;
        stream
            .set_nodelay(true)
            .map_err(|e| KeycardError::CardComm(e.to_string()))?;
        Ok(Self { stream })
    }

    fn write_frame(&mut self, body: &[u8]) -> Result<()> {
        let len = u16::try_from(body.len())
            .map_err(|_| KeycardError::CardComm("APDU exceeds 65535 bytes".into()))?;
        self.stream
            .write_all(&len.to_be_bytes())
            .and_then(|_| self.stream.write_all(body))
            .map_err(|e| KeycardError::CardComm(format!("sim write: {e}")))
    }

    fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut lb = [0u8; 2];
        self.stream
            .read_exact(&mut lb)
            .map_err(|e| KeycardError::CardComm(format!("sim read len: {e}")))?;
        let n = u16::from_be_bytes(lb) as usize;
        let mut buf = vec![0u8; n];
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| KeycardError::CardComm(format!("sim read body: {e}")))?;
        Ok(buf)
    }

    /// Reset the simulated card (fresh RAM). The server replies with an empty frame.
    pub fn reset(&mut self) -> Result<()> {
        self.write_frame(&[])?;
        let _ = self.read_frame()?;
        Ok(())
    }
}

impl CardTransport for SimTransport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        self.write_frame(apdu)?;
        self.read_frame()
    }
}
