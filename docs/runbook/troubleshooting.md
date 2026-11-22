# When things break

Observed failure modes, and what causes them.

## Build

**`LNK1104: cannot open file …exe`**
A running binary is holding it. Close the client or harness window. That is
the whole explanation — it is not a corrupt build.

**Everything rebuilds when you changed one line**
You set a `CARGO_PROFILE_*` variable. Profile changes are part of the cache
key, so the flag invalidates the world — and removing it invalidates it
again. Use `-j N` to limit parallelism instead.

**A build is killed with no error**
Memory. Linking `kenter-ui` takes on the order of 1.7 GB resident; alongside
a browser and an editor that is enough for the OS, or a supervising process,
to kill it. `-j 2`, or close something.

**Builds feel slow even when nothing changed**
Check `target/`. On a long-lived checkout it reaches hundreds of thousands
of files, and cargo stats all of them on every invocation. `cargo clean`,
or `cargo-sweep` to drop only the old artifacts.

**`cargo test` passes but `cargo build` fails**
`cargo test` does not build examples. Something still references a deleted
module. `cargo build --workspace --examples`.

## Cards

**"Opening a SecureChannel" fails**
**Stop.** Do not retry in a loop — repeated failed opens can exhaust attempt
counters. The usual cause is physical: card position or reader power. Move
the card.

**A card derives the wrong keys but nothing errors**
You are on the duress PIN. It verifies successfully with `9000` and switches
to a decoy tree — empty notes, unrelated keys, its own counter. This is the
single most confusing failure in the system, because every layer reports
success.

**PIN attempts disappearing**
Something is sending a hard-coded or wrong PIN. Pass the PIN to tests and
examples through `KENTER_CARD_PIN`, never in code: cards block permanently
after a fixed number of failures.

**Erratic hardware results**
Card at the edge of contactless range. The channel drops mid-command and the
failure reads like a protocol bug.

## Camera

**Black window, no frames**
Another process holds the device — very often a previous run that was killed
rather than closed, since a killed process never runs `Drop`. Check for stray
processes and verify they are gone.

**"Hardware MFT failed to start streaming… lack of hardware resources"**
Same cause. The device has not been released yet.

**A sharp-looking symbol will not read**
Two likely causes. Either the symbol fills the frame edge to edge and its
**quiet zone** is cropped — back off until there is white paper all round —
or the preview is lying to you: it is downscaled, so a frame that is soft at
full resolution still looks clean at preview size.

**Camera opens but reads nothing at any distance**
Check the resolution it negotiated. Below about 4 pixels per module nothing
will read, and too few pixels looks exactly like bad focus. See
[Paper and camera](/testing/paper).

## Network

**Node authenticates, then disconnects**
The relay has roster gating on and the node's address is not on that roster
(`auth_failed: not on roster`). Check the relay's `ROSTER_CONTRACT_ID`.

**`source .env` breaks**
`SOROBAN_NETWORK_PASSPHRASE` contains spaces and a `;`, and is unquoted.

**A print stalls on one position**
The selected pair is not connected to the relay the print goes through.
Check it through the relay: `/proxy/<G...>/kenter/health`. A selected pair
that stays silent past the serve timeout is skipped for the runner-up.

**The wallet skips a node that is up**
The node's roster endpoint names a relay that is not in the build's relay
list (`Profile::relays`). Wallets reach nodes only through those relays.

**Every node is refused by the relay at once**
The relay is rate limiting nginx's address instead of each client's. nginx
must set `X-Real-IP`, and its address must be in `TUNNLER_TRUSTED_PROXIES`.

**Prints fail with a 504 from the relay's nginx**
The location serving `/proxy` has nginx's default 60-second read timeout. A
node answers `extend` only after its on-chain `confirm_link` lands; set
`proxy_read_timeout 150`. See [Deployment](/DEPLOY#configure-nginx).

## Backup and restore

**A backup restores nothing, and says so**
If the report shows zero added and zero failed, that is usually correct: restore is **additive** and skips notes already held. Scanning your
own backup into a live wallet is a no-op by design, and a successful
verification.

**A paper sheet reads some symbols and not others**
If the failures are *not* ordered by density — a less dense symbol failing
while a denser one reads — then density is not the variable. Look at
framing, focus, and glare across the page.

**Restore refuses a sheet outright**
It belongs to a different wallet. Every symbol carries the wallet
fingerprint in cleartext precisely so this can be said before any key is
involved.

## General

**`pkill` does not kill it**
Unreliable on Windows. Use `Stop-Process`, and verify the process is gone.

**A test fails only under load**
It is sitting on a margin. Several thresholds in this codebase carry margin
for this reason: the paper scan floor is 3000px, although 2400px reads on an
idle machine, because 2400px is not reliable under parallel load.
