[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("dev", "stable")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [string]$Version,

    [string]$RepoRoot = "C:\Users\privacy\ZapretKVN-local-release",
    [string]$ManifestPath = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    & $Executable @Arguments | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable failed with exit code $LASTEXITCODE"
    }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Stop-ReleaseProcesses([string]$Root) {
    $ownedRoots = @(
        [IO.Path]::GetFullPath((Join-Path $Root "dist\ZapretKVN")),
        [IO.Path]::GetFullPath((Join-Path $Root "core"))
    )
    $names = @("ZapretKVN", "sing-box", "xray", "tun2socks")
    foreach ($process in Get-Process -Name $names -ErrorAction SilentlyContinue) {
        $path = $null
        try { $path = $process.Path } catch { $path = $null }
        if (-not $path) { continue }
        $resolved = [IO.Path]::GetFullPath($path)
        $owned = $ownedRoots | Where-Object {
            $resolved.StartsWith($_, [StringComparison]::OrdinalIgnoreCase)
        }
        if ($owned) {
            Write-Host "[release] stopping $($process.ProcessName) from $resolved"
            Stop-Process -Id $process.Id -Force
            Wait-Process -Id $process.Id -Timeout 15 -ErrorAction SilentlyContinue
        }
    }
}

function Assert-Workspace([string]$Root, [string]$ExpectedCommit, [string]$ExpectedVersion) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root ".git"))) {
        throw "Release workspace is missing: $Root"
    }
    Set-Location -LiteralPath $Root
    Invoke-Native "git" @("fetch", "origin", "main", "--tags")
    Invoke-Native "git" @("switch", "--detach", $ExpectedCommit)
    $actualCommit = (& git rev-parse HEAD).Trim()
    if ($actualCommit -ne $ExpectedCommit) {
        throw "Windows workspace SHA mismatch: $actualCommit"
    }
    $source = Get-Content -LiteralPath (Join-Path $Root "xray_fluent\constants.py") -Raw
    if (-not $source.Contains("APP_VERSION = `"$ExpectedVersion`"")) {
        throw "APP_VERSION does not match $ExpectedVersion"
    }
    $unexpected = @(
        git status --short --untracked-files=all |
            Where-Object { $_ -notmatch "^\?\? package-zapret-kvn\.ps1$" }
    )
    if ($unexpected.Count -ne 0) {
        $unexpected | Write-Host
        throw "Windows release workspace contains unexpected changes"
    }
}

function Install-VerifiedCore([string]$Root) {
    $lockFile = Join-Path $Root "scripts\core-lock.windows-x64.json"
    $archive = Join-Path $Root ".cache\core-bundle\core-windows-x64.7z"
    $stamp = "$archive.lock.sha256"
    $lockHash = Get-Sha256 $lockFile
    $cachedHash = if (Test-Path -LiteralPath $stamp) {
        (Get-Content -LiteralPath $stamp -Raw).Trim().ToLowerInvariant()
    } else { "" }
    if (-not (Test-Path -LiteralPath $archive) -or $cachedHash -ne $lockHash) {
        Write-Host "[release] rebuilding pinned core bundle"
        & (Join-Path $Root "scripts\build_core_bundle.ps1")
    } else {
        Write-Host "[release] reusing pinned core bundle for lock $lockHash"
    }
    & (Join-Path $Root "scripts\install_core_bundle.ps1")
}

function Ensure-DependenciesAndTests([string]$Root) {
    $python = Join-Path $Root ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $python)) {
        Invoke-Native "py" @("-3", "-m", "venv", (Join-Path $Root ".venv"))
    }
    Invoke-Native $python @("-m", "pip", "install", "-r", (Join-Path $Root "requirements.txt"))
    Invoke-Native $python @("-m", "pip", "check")
    Invoke-Native $python @("-m", "unittest", "discover", "-s", "tests", "-v")
}

function Build-Application([string]$Root) {
    Stop-ReleaseProcesses $Root
    $python = Join-Path $Root ".venv\Scripts\python.exe"
    Invoke-Native $python @((Join-Path $Root "build.py"), "--no-zip")
    $exe = Join-Path $Root "dist\ZapretKVN\ZapretKVN.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Built ZapretKVN.exe is missing"
    }
    return $exe
}

function Test-ShippedTemplates([string]$Root) {
    $sourceRoot = (Resolve-Path (Join-Path $Root "data\templates")).Path
    $templates = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File)
    foreach ($template in $templates) {
        $relative = $template.FullName.Substring($sourceRoot.Length).TrimStart("\")
        foreach ($destinationRoot in @(
            (Join-Path $Root "dist\ZapretKVN\data\templates"),
            (Join-Path $Root "dist\ZapretKVN\assets\template-update")
        )) {
            $destination = Join-Path $destinationRoot $relative
            if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) {
                throw "Missing shipped template: $destination"
            }
            if ((Get-Sha256 $template.FullName) -ne (Get-Sha256 $destination)) {
                throw "Shipped template mismatch: $destination"
            }
        }
    }
    return $templates.Count
}

function Find-SevenZip {
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidate = Join-Path $env:ProgramFiles "7-Zip\7z.exe"
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    throw "7-Zip is not installed"
}

function New-StableAssets([string]$Root, [string]$ReleaseVersion) {
    $sevenZip = Find-SevenZip
    $tag = "v$ReleaseVersion"
    $dist = Join-Path $Root "dist"
    $portable = Join-Path $dist "ZapretKVN"
    $coreBundle = Join-Path $Root ".cache\core-bundle\core-windows-x64.7z"
    $sfx = Join-Path $dist "ZapretKVN-$tag-windows-x64.exe"
    $zip = Join-Path $dist "ZapretKVN-$tag-windows-x64.zip"
    $checksum = "$zip.sha256"
    $archive = Join-Path $dist "ZapretKVN-$tag-windows-x64.7z"
    $releaseCore = Join-Path $dist "ZapretKVN-cores-$tag-windows-x64.7z"
    $outputs = @($sfx, $zip, $checksum, $archive, $releaseCore)

    foreach ($output in $outputs) {
        if (Test-Path -LiteralPath $output) {
            Remove-Item -LiteralPath $output -Force
        }
    }
    Push-Location -LiteralPath $portable
    try {
        Invoke-Native $sevenZip @("a", "-bd", "-t7z", "-mx=5", "-sfx", $sfx, "*")
        Invoke-Native $sevenZip @("a", "-bd", "-tzip", "-mx=5", $zip, "*")
        Invoke-Native $sevenZip @("a", "-bd", "-t7z", "-mx=5", $archive, "*")
    }
    finally {
        Pop-Location
    }
    Copy-Item -LiteralPath $coreBundle -Destination $releaseCore
    $zipHash = Get-Sha256 $zip
    [IO.File]::WriteAllText($checksum, "$zipHash`n", [Text.Encoding]::ASCII)
    foreach ($testFile in @($sfx, $zip, $archive, $releaseCore)) {
        Invoke-Native $sevenZip @("t", "-bd", $testFile)
    }

    return @($outputs | ForEach-Object {
        $item = Get-Item -LiteralPath $_
        if ($item.Length -le 0) { throw "Empty release asset: $($_)" }
        [ordered]@{
            name = $item.Name
            path = $item.FullName
            size = $item.Length
            sha256 = Get-Sha256 $item.FullName
        }
    })
}

Assert-Workspace $RepoRoot $Commit $Version
Stop-ReleaseProcesses $RepoRoot
Install-VerifiedCore $RepoRoot
Ensure-DependenciesAndTests $RepoRoot
$exePath = Build-Application $RepoRoot
$templateCount = Test-ShippedTemplates $RepoRoot
$assets = if ($Mode -eq "stable") { @(New-StableAssets $RepoRoot $Version) } else { @() }

if (-not $ManifestPath) {
    $ManifestPath = Join-Path $RepoRoot ".cache\release\v$Version\$Mode-manifest.json"
}
$manifestDirectory = Split-Path -Parent $ManifestPath
New-Item -ItemType Directory -Force -Path $manifestDirectory | Out-Null
$manifest = [ordered]@{
    schema = 1
    mode = $Mode
    version = $Version
    commit = $Commit
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
    executable = [ordered]@{
        path = $exePath
        size = (Get-Item -LiteralPath $exePath).Length
        sha256 = Get-Sha256 $exePath
    }
    templates_verified = $templateCount
    assets = $assets
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding utf8
Write-Host "[release] $Mode gate complete: $ManifestPath"
