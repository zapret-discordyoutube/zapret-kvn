[CmdletBinding()]
param(
    [string]$CoreDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (-not $CoreDirectory) {
    $CoreDirectory = Join-Path (Split-Path -Parent $PSScriptRoot) "core"
}

$manifestPath = Join-Path $CoreDirectory "core-manifest.windows-x64.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Core manifest not found: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([int]$manifest.schema -ne 1 -or [string]$manifest.platform -ne "windows-x64") {
    throw "Unsupported core manifest: $manifestPath"
}

foreach ($file in $manifest.files) {
    $path = Join-Path $CoreDirectory ([string]$file.name)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing core file: $($file.name)"
    }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedHash = ([string]$file.sha256).ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Core file hash mismatch for $($file.name): expected $expectedHash, got $actualHash"
    }
}

$singBoxSource = $manifest.sources | Where-Object { [string]$_.id -eq "sing-box-extended" } | Select-Object -First 1
if (-not $singBoxSource -or [string]$singBoxSource.version -notmatch "extended") {
    throw "Core manifest does not identify an extended sing-box build"
}
$singBoxPath = Join-Path $CoreDirectory "sing-box.exe"
if (-not ($manifest.PSObject.Properties.Name -contains "singbox_build")) {
    throw "Missing patched sing-box build provenance"
}
$frontBuild = $manifest.singbox_build
if ([string]$frontBuild.commit -notmatch '^[0-9a-f]{40}$' -or
    [string]$frontBuild.udp_patch.patch_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$frontBuild.binary_sha256 -ne (Get-FileHash -LiteralPath $singBoxPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw "Patched sing-box source/binary provenance mismatch"
}
$singBoxVersionOutput = (& $singBoxPath version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Bundled sing-box failed its version command with exit code $LASTEXITCODE"
}
$expectedSingBoxVersion = ([string]$singBoxSource.version).TrimStart("v")
if ($singBoxVersionOutput -notmatch [regex]::Escape($expectedSingBoxVersion)) {
    throw "Bundled sing-box version output does not match $($singBoxSource.version)"
}
$xraySource = $manifest.sources | Where-Object { [string]$_.id -eq "xray-core" } | Select-Object -First 1
if (-not $xraySource) { throw "Core manifest does not identify Xray" }
$xrayPath = Join-Path $CoreDirectory "xray.exe"
$xrayVersionOutput = (& $xrayPath version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Bundled Xray failed its version command with exit code $LASTEXITCODE"
}
$expectedXrayVersion = ([string]$xraySource.version).TrimStart("v")
if ($xrayVersionOutput -notmatch [regex]::Escape($expectedXrayVersion)) {
    throw "Bundled Xray version output does not match $($xraySource.version)"
}
$hysteriaSource = $manifest.sources | Where-Object { [string]$_.id -eq "hysteria" } | Select-Object -First 1
if (-not $hysteriaSource) { throw "Core manifest does not identify official Hysteria" }
$hysteriaPath = Join-Path $CoreDirectory "hysteria.exe"
$hysteriaVersionOutput = (& $hysteriaPath version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "Bundled Hysteria failed its version command with exit code $LASTEXITCODE"
}
$expectedHysteriaVersion = ([string]$hysteriaSource.version).Replace("app/", "")
if ($hysteriaVersionOutput -notmatch [regex]::Escape($expectedHysteriaVersion)) {
    throw "Bundled Hysteria version output does not match $($hysteriaSource.version)"
}

Write-Host "[core] verified $($manifest.files.Count) files"
$amneziaSource = @($manifest.sources | Where-Object { [string]$_.id -eq "amnezia" })
if ($amneziaSource.Count -ne 1) { throw "Core manifest must identify official Amnezia" }
$amneziaOutput = (& (Join-Path $CoreDirectory "zapret-amnezia.exe") --version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $amneziaOutput -notmatch [regex]::Escape([string]$amneziaSource[0].version)) {
    throw "Bundled Amnezia version does not match its manifest"
}
Write-Host "[core] Amnezia: $($amneziaSource[0].version)"
Write-Host "[core] sing-box: $($singBoxSource.version)"
Write-Host "[core] Hysteria: $($hysteriaSource.version)"
