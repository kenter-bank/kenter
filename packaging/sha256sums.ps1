# Add or replace a file's line in dist\SHA256SUMS (the format sha256sum -c
# reads: "<hex>  <name>"). The release signature, when there is one, signs
# this file.

param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'

$file = Get-Item $Path
$sums = Join-Path $file.DirectoryName 'SHA256SUMS'
$hash = (Get-FileHash -Algorithm SHA256 $file.FullName).Hash.ToLower()
$lines = @()
if (Test-Path $sums) {
    # @(...): one surviving line would otherwise be a string, and += would
    # glue the next line onto it.
    $lines = @(Get-Content $sums | Where-Object { $_ -and -not $_.EndsWith("  $($file.Name)") })
}
$lines += "$hash  $($file.Name)"
# LF endings and no BOM, so sha256sum -c accepts it on any platform.
[System.IO.File]::WriteAllText($sums, (($lines | Sort-Object { $_.Substring(66) }) -join "`n") + "`n")
Write-Host "$hash  $($file.Name)"
