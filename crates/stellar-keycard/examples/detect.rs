/// Detect connected Keycard readers and cards.
///
/// Usage: cargo run -p stellar-keycard --example detect

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("stellar_keycard=debug")
        .init();

    // Step 1: List all readers
    println!("=== Stellar Keycard: Device Detection ===\n");

    match stellar_keycard::Transport::list_readers() {
        Ok(readers) => {
            if readers.is_empty() {
                println!("No PC/SC readers found.");
                println!("\nMake sure:");
                println!("  - Keycard Shell is connected via USB-C, or");
                println!("  - A USB NFC reader is plugged in");
                return;
            }
            println!("Found {} reader(s):", readers.len());
            for (i, name) in readers.iter().enumerate() {
                println!("  [{}] {}", i, name);
            }
        }
        Err(e) => {
            println!("Failed to list readers: {}", e);
            println!("\nOn Linux, make sure pcscd is running:");
            println!("  sudo systemctl start pcscd");
            return;
        }
    }

    // Step 2: Connect and SELECT
    println!("\nConnecting to first available card...");

    let mut transport = match stellar_keycard::Transport::connect() {
        Ok(t) => t,
        Err(stellar_keycard::KeycardError::NoCard) => {
            println!("No card detected in reader.");
            println!("\nInsert a Keycard into the Shell or tap on the NFC reader.");
            return;
        }
        Err(e) => {
            println!("Connection failed: {}", e);
            return;
        }
    };

    println!("Connected.\n");

    // Step 3: SELECT Keycard applet
    println!("Selecting Keycard applet...");

    match transport.select_keycard() {
        Ok(info) => {
            let sc_hex = hex::encode(&info.secure_channel_public_key);
            println!("\n=== Keycard Detected ===");
            println!("  Applet initialized: {}", info.initialized);
            println!(
                "  SC public key:      {}...{} ({} bytes, secp256k1)",
                &sc_hex[..8.min(sc_hex.len())],
                &sc_hex[sc_hex.len().saturating_sub(8)..],
                info.secure_channel_public_key.len(),
            );

            if info.initialized {
                println!(
                    "  Applet version:     {}.{}",
                    info.app_version.0, info.app_version.1
                );
                println!("  Instance UID:       {}", hex::encode(&info.instance_uid));
                println!("  Key initialized:    {}", info.key_initialized);
                println!("  Pairing slots:      {}", info.remaining_pairing_slots);
                if !info.key_initialized {
                    println!("\n  Applet is set up but has no master key yet.");
                }
                println!("\nReady for pairing + secure channel.");
            } else {
                println!("\n  Card is a Keycard-compatible applet but is UNINITIALIZED");
                println!("  (no PIN/PUK/pairing secret set). Next step: INIT.");
            }
        }
        Err(stellar_keycard::KeycardError::NotKeycard) => {
            println!("Card is not a Keycard (unexpected SELECT response).");
            println!("Make sure the card has the Keycard applet installed.");
        }
        Err(e) => {
            println!("SELECT failed: {}", e);
        }
    }
}
