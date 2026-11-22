# Build the Kenter MSI for Windows x64.
#
#   powershell -File packaging\windows\build-msi.ps1            # testnet build
#   powershell -File packaging\windows\build-msi.ps1 -Mainnet   # needs KENTER_MAINNET_MINT/_ROSTER set
#
# Needs: the Rust toolchain (rust-toolchain.toml), and WiX 5 as a .NET tool:
#   dotnet tool install --global wix --version 5.0.2
#
# Output: dist\kenter-<version>-<network>-x64.msi, and its line in
# dist\SHA256SUMS. The MSI is not signed; signing is one step to add here
# once a code-signing certificate exists.

param([switch]$Mainnet)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $repo

$version = (Select-String -Path crates\kenter-node\Cargo.toml -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$network = if ($Mainnet) { 'mainnet' } else { 'testnet' }
$netFeature = @()
if ($Mainnet) {
    if (-not $env:KENTER_MAINNET_MINT -or -not $env:KENTER_MAINNET_ROSTER) {
        throw 'A mainnet build needs KENTER_MAINNET_MINT and KENTER_MAINNET_ROSTER (kenter_client::network).'
    }
    $netFeature = @('--features', 'kenter-client/mainnet')
    if (-not $env:KENTER_MAINNET_RELAYS) {
        throw 'A mainnet build needs KENTER_MAINNET_RELAYS: a wallet reaches nodes only through built-in relays.'
    }
} elseif (-not $env:KENTER_TESTNET_MINT -or -not $env:KENTER_TESTNET_ROSTER -or -not $env:KENTER_TESTNET_RELAYS) {
    throw 'A testnet build needs KENTER_TESTNET_MINT, KENTER_TESTNET_ROSTER and KENTER_TESTNET_RELAYS (kenter_client::network).'
}

Write-Host "Building Kenter $version ($network)"
cargo build --release --locked -p kenter-node --features tray --bins @netFeature
if ($LASTEXITCODE) { throw 'cargo build kenter-node failed' }
# packaged: skins only from beside the executable, no source-tree fallback.
cargo build --release --locked -p kenter-ui --bin kenter-ui --features packaged @netFeature
if ($LASTEXITCODE) { throw 'cargo build kenter-ui failed' }

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    $candidate = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
    if (-not (Test-Path $candidate)) { throw 'WiX not found: dotnet tool install --global wix --version 5.0.2' }
    $wix = $candidate
} else {
    $wix = $wix.Source
}

# Pinned build tools: a different WiX is a different
# installer.
$wixVersion = (& $wix --version).Trim()
if (-not $wixVersion.StartsWith('5.0.2')) { throw "WiX 5.0.2 required, found $wixVersion" }

New-Item -ItemType Directory -Force dist | Out-Null
$msi = "dist\kenter-$version-$network-x64.msi"
& $wix build packaging\windows\kenter.wxs -arch x64 `
    -d "Version=$version" `
    -d "BinDir=$repo\target\release" `
    -d "AssetsDir=$repo\packaging\assets" `
    -d "SkinsSrc=$repo\crates\kenter-ui\skins\kenter" `
    -o $msi
if ($LASTEXITCODE) { throw 'wix build failed' }

& "$PSScriptRoot\..\sha256sums.ps1" $msi
Write-Host "Built $msi"
