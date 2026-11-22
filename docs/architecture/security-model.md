# Security model

This page states what each component trusts, the main threats and what stops
each one, and the limits the system has by design. It is a map, not a proof:
the reasoning behind each mechanism is on the page linked from it.

Kenter is on testnet and has had no independent security review. Do not put
real money in it.

## What each component trusts

| Component | Trusts | Does not trust |
|---|---|---|
| **Mint contract** | The Soroban host's crypto (`ed25519_verify`, SHA-256, BLS12-381 pairing); drand quicknet's group key, fixed at deploy; the roster for membership and `joined_at`; the pay token's contract | Every caller. Every state change authenticates its actor, and every value that identifies a note is read from the mint's own record, not from the caller |
| **Roster contract** | Nothing beyond its own records | Nobody can remove a node or move a bond. There is no admin |
| **Node** | Its own pair keys; the mint's slot record | The depositor, the relay, any other node. Every extend request is checked against the slot before work is done |
| **Relay** | Stellar-signed JWTs and the on-chain roster, to admit node sessions | Nothing it forwards carries authority |
| **Wallet** | Its seed and vault; the one Soroban RPC endpoint it is configured with; the relays built into the release; drand mirrors only as a source of bytes the mint will verify | Note files it is handed, backups it restores, node replies, the relay |
| **Holder** | Their own copy of the seed phrase and the note files | Nobody holds value for them, and nobody can restore it |

Two properties of the contracts shape everything else:

- **No admin and no upgrade path.** The mint has no admin control over
  monetary logic, no withdrawal entry point and no way to change its code or
  parameters. The roster has no admin either. A mistake in a deployed
  contract cannot be patched in place; it needs a new deployment, and notes
  printed on the old one stay on the old one.
- **Records are keyed by slot.** A note's record is `Token(slot_id)`, and
  slot ids come from a counter the contract issues. Nothing a caller names
  can collide with another note's record. Each slot holds at most one record,
  ever.

## Threats and what stops them

### Stealing a note without holding it

| Threat | What stops it |
|---|---|
| **Interior nodes collude to rebuild the ephemeral secret.** Each shard is derivable by either member of its pair, so all interior pairs together know every interior shard | The depositor holds the first and last pairs and builds the closing link on its own machine; no node ever sees it. Path B needs every link and Path A needs every shard, so no coalition of nodes can redeem a note it never received |
| **A forged chain built from public data** (the ephemeral key, event id and pair count are all public) | `register_token` commits `chain_hash = SHA-256(chain_data)`. Path B requires the submitted chain to hash to it before anything else is checked |
| **Lifting a chain off a failed redemption.** Presenting the chain publishes it; a transaction that fails on chain publishes it while the note stays live | Pure-bearer redemption on both paths also requires a signature from the note's **claim key** over the recipient. The claim secret is random, generated at assembly, stored only in the file and never sent anywhere. A signature for one recipient is useless to anyone else |
| **Reusing a signature** from another deployment, another record or an earlier state | Every digest includes the mint's address and the slot id. Redemption digests include the recipient. Transfer digests include both commitments and a nonce that advances on every transfer |
| **Composing the ephemeral secret through the node network** (Path A's shard endpoint serves whoever asks) | Path A also requires the claim signature (pure bearer) or the owner proof (spend mode), so knowing the ephemeral secret proves construction, not possession |
| **A payer redeeming after paying** | Spend mode: the mint moves ownership on `spend`, and redemption requires the current owner's key. In pure bearer this is the copy property and is not prevented |
| **A thief with the file** | Spend mode: still needs the owner key, derived from the seed and never sent to a node. Pure bearer: the thief can redeem |

See [Bearer token format](/bearer-token-format), [Bearer and spend
mode](/architecture/spend-mode) and [Tokens and their
lifecycle](/architecture/tokens).

### Steering or abusing a print

| Threat | What stops it |
|---|---|
| **The depositor chooses its own interior pairs** (fee capture, fake work records) | The depositor names only its end pairs. Interior positions go to the lowest scores under a seed from a drand round that did not exist at request |
| **Grinding the seed** | The round is fixed at request, `beacon_lead` rounds ahead. A BLS signature is unique, so whoever posts it chooses nothing |
| **Re-rolling a draw** by cancelling, declining to seed, or letting the slot expire | Once round `R` is published, abandoning a print burns `2 · node_fee` per unconfirmed interior position. Expiry is free only for a slot that was never seeded, which locks the deposit for the whole print window |
| **Skipping honest pairs** to reach one's own runners-up | Each skip burns `2 · node_fee`, paid by the depositor |
| **Recombining addresses into the best-scoring pair** after the seed is public | A pair may claim only if it was registered together in a ledger before the request |
| **Entering an honest pair into a print it did not agree to** | `claim_position` and `register_pair` need both members' signatures |
| **Racing claims** with more bots or a faster connection | Scores rank, not arrival. A later, lower score displaces a higher one |
| **Fresh Sybil nodes** | Joining the roster locks a bond (`min_stake`) for an unbonding period after leaving. On mainnet, `min_node_age` keeps a new node out of selection for its first day |
| **Flooding the mint with slots** to drain node balances | Each daemon spends from a daily allowance with a reserve for short lists and stops at a low-balance floor. The flood's real cost is the forfeit its sender pays |
| **Arbitrary extend requests** sent through the relay | A node extends only a request matching the slot: its event id, exactly the confirmed links, each signed by the assigned pair, and this pair next |
| **A node claiming fees for work it did not do** | Fees are credited only to interior participants recorded on chain. An abandoned print pays only the address that confirmed each link |

See [Node selection](/architecture/node-selection).

### Learning who is paying

| Threat | What stops it |
|---|---|
| **A node operator learns the depositor's IP** by naming a relay of its own in its roster endpoint | The wallet reaches nodes only through relays built into the release (`Profile::relays`). An endpoint naming any other host, an IP literal or `localhost` is treated as a node that does not serve |
| **The relay links an IP to a Stellar address** | The depositor sends plain HTTPS to the relay's open proxy route and signs in with nothing. The relay learns the IP, not the address |
| **A node redirects the wallet elsewhere** | The wallet follows no redirects and reads at most 256 KB of a reply |
| **Owner commitments link a holder's notes** | A fresh owner key per receipt. Only the opt-in static pay tag is reused |

### Trusting the chain view

The wallet's receive gates and balance read the mint's state through one
Soroban RPC endpoint. The client:

- checks that every returned ledger entry carries the mint's contract address
  and the exact key it asked for;
- refuses a record whose mode it cannot parse, instead of reading it as pure
  bearer;
- treats a missing record as a question, reading the `Redeemed` marker and
  then simulating `get_token_state`, which restores archived entries;
- refuses a non-loopback `http://` endpoint;
- caps the resource fee it will sign;
- names the endpoint on the receive screen ("checked against").

The network is fixed when the binary is built. A custom RPC endpoint is
checked against the build's network passphrase, and a mainnet build's
contract ids are compiled in and cannot be overridden.

### Restoring

| Threat | What stops it |
|---|---|
| **A fabricated note in a backup** | `backup::check` parses each note, verifies chain integrity and checks that its id matches its bytes. A note failing any check is rejected, not imported |
| **Overwriting a held note from a backup** | Restore is additive. It never replaces a note the wallet holds |
| **Mixing symbols from different paper sheets** | Each paper symbol carries the wallet fingerprint and a digest of its whole item |

See [Data formats](/architecture/data-formats).

## Limits, by design

These are properties of the system, not defects awaiting a fix.

- **Loss is final.** No party can restore a lost note, a lost owner key or a
  lost seed. The seed alone recovers nothing: the note files must be backed
  up too.
- **A pure-bearer copy is the original.** Anyone with the file, including a
  photograph of a paper backup, can redeem it. The wallet records every way a
  note's bytes left it (`ExportLog`) so the holder can judge exposure.
- **The gates verify against one endpoint.** Soroban RPC serves state, not
  proofs. A dishonest endpoint can claim a live note does not exist, serve a
  stale record, or fabricate a live record that names the right contract and
  key, carries the note's chain hash and passes every gate. The defence is to
  point the client at an endpoint you run. Cross-checking two endpoints
  configured from the same place would not raise the bar.
- **The ends of a payment are public.** The depositing account and the
  redemption payout are on the ledger in both modes. Path B also publishes
  the note's chain at redemption. Spend mode puts every transfer on the
  ledger.
- **Interior nodes see metadata.** A print's nodes learn its event id,
  amount, timing and depositor address, even though they cannot redeem it.
- **Shard independence is assumed, not checked.** The mint records each
  link's partial key but does not verify that it derives from the
  confirming node's identity. A party holding many roster addresses can
  supply many links. What protects a note is the holder's closing link, not
  the independence of the interior.
- **The end-pair exemption is positional.** The mint does not roster-check
  or distinctness-check links `0` and `total_pairs − 1`; it only declines to
  check them, because the depositor names them and only it is exposed. No
  client or deployment may place a third-party node at an end position.
- **A selected pair can withhold its reply after confirming.** It is paid
  for that link and the print ends in a cancel. This is griefing that pays
  nothing extra, needs a staked pair that won the draw, and is visible on the
  ledger.
- **The relay can refuse traffic.** To the depositor that looks like a dead
  node: it skips at a fee and a runner-up serves. A relay that blocked
  honest pairs selectively could bias which runners-up serve.
- **Path A's shard request authorizes nobody.** A node verifies the
  requester's signature against an address the requester supplies, so anyone
  can ask. That cannot reach a payout (Path A also needs the claim key or
  owner proof), but anyone holding the public inputs can deny Path A
  redemption of a link for up to 15 minutes at a time. Path B is unaffected,
  and the desktop client redeems by Path B only.
- **A failed transfer stays live.** A broadcast `spend` authorization stays
  valid until the note's nonce moves. The holder must retry it or spend the
  note to themselves; paying with a different note can pay twice.
- **drand is a dependency for printing.** If it stops, no print can be
  seeded and open slots refund in full on expiry. Redemption never touches
  it. A colluding threshold of drand operators could predict seeds, which
  gives a depositor its choice of pairs back: fee capture, not theft.
- **An issued asset can be frozen.** If the mint escrows an issued asset
  whose issuer has `auth_revocable` set, the issuer can freeze the mint's
  balance. Native XLM has no issuer. Every note records the mint and the
  asset it pays in (its mint binding) so a payee can see which they hold.
- **Rent.** A note's ledger record has a 7-day floor and the holder extends
  it with `bump_token`. An archived record is still redeemable: Soroban
  restores it when a transaction names it, and the restore fee falls on
  whoever touches it next. See [Ledger costs](/LEDGER_COSTS).
