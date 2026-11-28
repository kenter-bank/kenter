# Setting up

What you need on a fresh machine to build Kenter and run its tests.

## Toolchain

**Rust, pinned.** `rust-toolchain.toml` at the repository root pins the
toolchain (currently 1.91.1) and the `wasm32v1-none` target for the whole
tree, contracts included. rustup reads it from any subdirectory and installs
that version on first use, so all you need is rustup itself.

The pin exists for two reasons. Newer stable releases can break the contract
dependencies (`soroban-sdk` depends on `ethnum`, which does not compile on
every newer compiler). And the mint is immutable, so the wasm deployed to
mainnet must be rebuildable byte for byte from a tagged commit, which
includes the compiler version. The workspace needs at least 1.89
(`std::fs::File::lock`, used by the wallet store lock) and uses edition 2024.

::: warning Contract builds depend on the build host
The same commit, toolchain and `stellar` CLI produce different contract wasm
on Windows and on Linux: the code is identical but functions are laid out in
a different order, so the hashes differ. Builds on x86_64 Linux agree with
each other. **Mainnet contracts are built and deployed on x86_64 Linux**, and
that is the platform to verify a deployed hash on. A Windows build is fine
for development and testnet, but its hash will not match a Linux build.
:::

To move the pin: change the channel, rebuild both contracts with
`stellar contract build`, and run the mint test suite plus the two
`wasm-bench` budget checks that `scripts/deploy_testnet.sh` runs.

**A C/C++ linker.** On Windows, Visual Studio Build Tools with the MSVC
toolchain. On Linux, `build-essential` or equivalent. On macOS, the Xcode
command line tools.

**The `stellar` CLI** for deploying contracts, funding test accounts and
running the rent keeper. Not needed to build or test the workspace.

**Node 18+** for the documentation site only. Nothing in the Rust build
needs it.

## Platform dependencies

### Linux packages

On Debian, Ubuntu or Pop!_OS, this is everything the workspace, the
contracts and the `stellar` CLI need:

```bash
sudo apt install build-essential pkg-config git curl ca-certificates \
  libssl-dev libpcsclite-dev libudev-dev libdbus-1-dev libclang-dev \
  libxkbcommon-dev libwayland-dev pcscd
```

| Package | Needed by |
|---|---|
| `build-essential`, `pkg-config` | linking, and finding the libraries below |
| `libssl-dev` | `openssl-sys`, through the HTTP stack |
| `libpcsclite-dev`, `pcscd` | smart card access (below) |
| `libudev-dev`, `libdbus-1-dev` | the `stellar` CLI (hardware wallets, OS keyring) |
| `libclang-dev` | crates that generate bindings at build time |
| `libxkbcommon-dev`, `libwayland-dev` | `kenter-ui` windowing |

Install the `stellar` CLI with the version the contracts were last built
with, from source:

```bash
cargo install --locked stellar-cli --version 23.4.1
```

### Smart card access (`stellar-keycard`)

Keycard custody uses PC/SC.

| Platform | Needs |
|---|---|
| Windows | `winscard.dll`, part of Windows; nothing to install |
| Linux | `pcscd` running, plus `libpcsclite-dev` to build |
| macOS | `PCSC.framework`, part of the OS |

You also need a reader. Development uses a USB NFC reader (ACR122U or
similar) and a Keycard. See
[Keycard hardware](/testing/keycard).

### Camera (`kenter-ui`, paper restore)

`nokhwa` compiles a different backend per platform, named per target in
`crates/kenter-ui/Cargo.toml`:

| Platform | Backend | Notes |
|---|---|---|
| Windows | `input-msmf` | Media Foundation; nothing to install |
| Linux | `input-v4l` | Your account must be in the `video` group |
| macOS | `input-avfoundation` | Needs `NSCameraUsageDescription` in an app bundle, which the build does not produce yet |

MJPEG decoding is **off** on purpose, so there is no `mozjpeg` and no NASM
requirement. See [Paper and camera](/testing/paper) for why, and for what it
means for capture resolution.

::: warning Only the Windows camera path has run
On Linux and macOS the dependency trees resolve and build. Neither has
opened a camera.
:::

## The workspace

```bash
git clone https://github.com/kenter-vault/kenter.git
cd kenter
cargo build
```

The workspace has thirteen crates. A cold build compiles several hundred
dependencies and takes a while. `kenter-ui` is the long pole: one large
crate whose link step dominates.

The contracts in `contracts/` are separate workspaces with their own
lockfiles; see [Build and run](/runbook/build-and-run#contracts).

## Configuration

### `.env`

A `.env` at the repository root holds local settings for development. **It
is gitignored and can contain secrets.** The repository ships no example
file. These are the readers and the keys each one takes from it:

| Reader | Keys |
|---|---|
| `kenter-tunnler` (local relay) | `TUNNLER_SERVER_SECRET`, `TUNNLER_DOMAIN`, `TUNNLER_HOST`, `TUNNLER_PORT`, `TUNNLER_LOG_LEVEL`, `ROSTER_CONTRACT_ID`, `SOROBAN_RPC_URL`, `SOROBAN_NETWORK_PASSPHRASE`, and the rest of the [relay configuration](/tunnler-api#configuration) |
| `kenter-systest` | `TUNNLER_SERVER_SECRET` (for the local relay it starts), `KENTER_SYSTEST_FUNDER_SECRET`, `KENTER_SYSTEST_MINT`, `KENTER_ROSTER` |
| `kenter-ui`, debug build | anything in the variable table below |
| `scripts/deploy_testnet.sh` | `XLM_SAC_CONTRACT_ID`, `USDC_SAC_CONTRACT_ID` only |
| `scripts/keeper.sh` | `KENTER_MINT`, `KENTER_ROSTER` only |

`kenter-tunnler` and `kenter-systest` load `.env` with `dotenvy`, which
searches the working directory and then its parents. The two scripts read
only the keys they name and never source the file.

A minimal file for running the system test:

```bash
TUNNLER_SERVER_SECRET=S...          # any fresh testnet seed; the local relay's identity
TUNNLER_HOST=127.0.0.1
TUNNLER_PORT=8000
KENTER_SYSTEST_FUNDER_SECRET=S...   # a funded testnet account holding USDC
XLM_SAC_CONTRACT_ID=C...            # for deploy_testnet.sh, see Testnet environment
USDC_SAC_CONTRACT_ID=C...
```

::: danger Quote values with spaces
`SOROBAN_NETWORK_PASSPHRASE` contains spaces and a `;`. Unquoted, it breaks
`source .env`. The `stellar` CLI also loads `.env` from the working
directory, which affects contract calls made from inside the repository;
see [Testnet environment](/TESTNET).
:::

### Environment variables the code reads

::: warning The GUI reads a `.env` only where told
These variables choose the mint every deposit escrows into and the vault
that is opened, so a `.env` picked up by accident could repoint a wallet
with nothing on screen to show it. `kenter-ui` therefore never searches
parent directories:

- `kenter-ui --env-file <path>` reads exactly that file, in any build.
- A **debug** build with no flag reads `./.env` in the working directory,
  and nowhere above it.
- A **release** build with no flag reads no file.

Either way it prints the file it read and every variable it set. A variable
already present in the real environment always wins. Settings shows the
live mint contract id.
:::

| Variable | Used by | Meaning |
|---|---|---|
| `KENTER_VAULT` | client, CLI | Path to the vault file |
| `KENTER_WALLET_DIR` | client, CLI | Where the note store lives |
| `KENTER_MINT` | client, CLI, node | Mint contract id. Testnet builds only; a mainnet build's contracts are fixed at build time |
| `KENTER_ROSTER` | client, CLI, node | Roster contract id. Testnet builds only |
| `KENTER_RPC` | client, CLI, node | Soroban RPC endpoint. Checked against the build's network passphrase before use |
| `KENTER_HORIZON` | client | Where **account** reads go. Soroban RPC has no `getAccount`, so sequence numbers and balances come from Horizon, by default SDF's public instance whatever RPC you chose. That instance sees every address the wallet touches. Set this if you run your own. Settings shows which is in use |
| `KENTER_NODE_HOME` | node | The installed node's home directory (keys and `node.json`) |
| `KENTER_NODE_SECRET` | node, development form | This node's Stellar secret |
| `KENTER_NODE_PARTNER_SECRET` | node, development form | Its pair partner's secret |
| `KENTER_CAMERA` | ui | Pin a camera by index or name substring |
| `KENTER_PAPER_MODULE_MM` | ui | Override the 0.30 mm paper module |
| `KENTER_CARD_PIN` | card tests | PIN for hardware tests; never hard-code one |
| `KENTER_CARD_DESTRUCTIVE` | card tests | Opt in to tests that wipe a card |
| `KENTER_SYSTEST_FUNDER_SECRET` | systest | Funding account for the system test |
| `KENTER_SYSTEST_MINT` | systest | Mint to test against (default: the testnet USDC mint) |
| `KENTER_TEST_SECRET` | tests | A fixed secret for deterministic tests |
| `KENTER_BLESS_VECTORS` | tests | Rewrite golden test vectors |
| `STELLAR_KEYCARD_SIM` | keycard | Point at a card simulator instead of a reader |

The network itself (testnet or mainnet, and its passphrase) is not a
variable. It is fixed when the binary is built: a build with the `mainnet`
feature talks to mainnet and nothing else. See
`crates/kenter-client/src/network.rs`.

### Build-time network settings

The contracts and relays a build uses are part of its network, so they are
read when the binary is **compiled**, not when it runs:

| Variable | Meaning |
|---|---|
| `KENTER_TESTNET_MINT`, `KENTER_MAINNET_MINT` | Mint contract id |
| `KENTER_TESTNET_ROSTER`, `KENTER_MAINNET_ROSTER` | Roster contract id |
| `KENTER_TESTNET_RELAYS`, `KENTER_MAINNET_RELAYS` | Comma-separated relay hosts (`host` or `host:port`, no scheme) |

A build without its contracts refuses to start, and a build without relays
reaches no node. On testnet, `KENTER_MINT` and `KENTER_ROSTER` can still
replace the contracts at run time; on mainnet they cannot. The packaging
scripts refuse to build without these set. Changing one triggers a rebuild of
the crates that read it.

::: danger Never put a secret on the command line
Secrets come from the environment or from files, never from argv. Argv is
visible to every process on the machine and lands in shell history.
:::

## Next

- [Build and run](/runbook/build-and-run)
- [Running the tests](/runbook/testing)
- [A local network](/runbook/local-network)
