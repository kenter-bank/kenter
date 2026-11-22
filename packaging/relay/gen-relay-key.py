#!/usr/bin/env python3
"""Generate a Stellar secret seed (S...) for the relay's identity, on the
relay itself, so the key never leaves it. Prints the seed on stdout only;
the setup script writes it straight into the root-owned env file.

Strkey: version byte 18 << 3 (seed), 32 random bytes, CRC16-XModem
little-endian, base32 without padding.
"""
import base64, os, struct

def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

payload = bytes([18 << 3]) + os.urandom(32)
seed = base64.b32encode(payload + struct.pack("<H", crc16_xmodem(payload))).decode().rstrip("=")
assert len(seed) == 56 and seed.startswith("S")
print(seed)
