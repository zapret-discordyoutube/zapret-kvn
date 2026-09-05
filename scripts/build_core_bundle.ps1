[CmdletBinding()]
param(
    [string]$LockFile = "",
    [string]$OutputArchive = "",
    [string]$DownloadCache = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $LockFile) {
    $LockFile = Join-Path $PSScriptRoot "core-lock.windows-x64.json"
}
if (-not $OutputArchive) {
    $OutputArchive = Join-Path $repoRoot ".cache/core-bundle/core-windows-x64.7z"
}
if (-not $DownloadCache) {
    $DownloadCache = Join-Path $repoRoot ".cache/core-downloads"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-VerifiedArchive($Source, [string]$CacheDirectory) {
    $archivePath = Join-Path $CacheDirectory ([string]$Source.archive)
    $expectedHash = ([string]$Source.sha256).ToLowerInvariant()
    if (Test-Path -LiteralPath $archivePath) {
        if ((Get-Sha256 $archivePath) -eq $expectedHash) {
            Write-Host "[core] cache hit: $($Source.id) $($Source.version)"
            return $archivePath
        }
        Remove-Item -LiteralPath $archivePath -Force
    }

    Write-Host "[core] downloading $($Source.id) $($Source.version)"
    $partialPath = "$archivePath.partial"
    Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    try {
        $curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
        $sourceUrls = @()
        if ($Source.PSObject.Properties.Name -contains "urls") {
            $sourceUrls = @($Source.urls | ForEach-Object { [string]$_ })
        }
        if ($sourceUrls.Count -eq 0) {
            $sourceUrls = @([string]$Source.url)
        }
        $downloaded = $false
        $lastDownloadError = $null
        foreach ($sourceUrl in $sourceUrls) {
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                try {
                    if ($curlCommand) {
                        $curlArguments = @(
                            "--fail", "--location",
                            "--connect-timeout", "30",
                            "--max-time", "120",
                            "--output", $partialPath,
                            $sourceUrl
                        )
                        $curlProcess = Start-Process -FilePath $curlCommand.Source -ArgumentList $curlArguments `
                            -NoNewWindow -Wait -PassThru
                        if ($curlProcess.ExitCode -ne 0) {
                            throw "curl.exe failed with exit code $($curlProcess.ExitCode)"
                        }
                    }
                    else {
                        Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri $sourceUrl -OutFile $partialPath
                    }
                    $downloaded = $true
                    break
                }
                catch {
                    $lastDownloadError = $_
                    Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
                    Write-Host "[core] download retry $attempt/2 for $($Source.id) from $sourceUrl"
                    Start-Sleep -Seconds 2
                }
            }
            if ($downloaded) {
                break
            }
        }
        if (-not $downloaded) {
            throw $lastDownloadError
        }
        $actualHash = Get-Sha256 $partialPath
        if ($actualHash -ne $expectedHash) {
            throw "SHA-256 mismatch for $($Source.archive): expected $expectedHash, got $actualHash"
        }
        Move-Item -LiteralPath $partialPath -Destination $archivePath -Force
    }
    finally {
        Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    }
    return $archivePath
}

$lock = Get-Content -LiteralPath $LockFile -Raw | ConvertFrom-Json
if ([int]$lock.schema -ne 1 -or [string]$lock.platform -ne "windows-x64") {
    throw "Unsupported core lock format: $LockFile"
}

$sevenZipCommand = Get-Command 7z -ErrorAction SilentlyContinue
$sevenZipPath = if ($sevenZipCommand) { $sevenZipCommand.Source } else { "" }
if (-not $sevenZipPath -and $env:ProgramFiles) {
    $candidate = Join-Path $env:ProgramFiles "7-Zip\7z.exe"
    if (Test-Path -LiteralPath $candidate) {
        $sevenZipPath = $candidate
    }
}
if (-not $sevenZipPath) {
    throw "7z is required to create the core bundle"
}

New-Item -ItemType Directory -Force -Path $DownloadCache | Out-Null
$outputDirectory = Split-Path -Parent $OutputArchive
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ZapretKVN-core-" + [guid]::NewGuid().ToString("N"))
$stagingDirectory = Join-Path $temporaryRoot "core"
$partialOutputArchive = "$OutputArchive.partial"
New-Item -ItemType Directory -Force -Path $stagingDirectory | Out-Null
$manifestFilesByName = [ordered]@{}
$python = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    & py -3 -m venv (Join-Path $repoRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Cannot prepare project Python for source core build" }
}
$inputHash = (& $python (Join-Path $PSScriptRoot "core_bundle_fingerprint.py") --root $repoRoot --lock $LockFile | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $inputHash -notmatch '^[0-9a-f]{64}$') { throw "Cannot fingerprint core build inputs" }

try {
    foreach ($source in $lock.sources) {
        $archivePath = Get-VerifiedArchive $source $DownloadCache
        $extractDirectory = Join-Path $temporaryRoot ([string]$source.id)
        $sourceKind = if ($source.PSObject.Properties.Name -contains "kind") { [string]$source.kind } else { "archive" }
        if ($sourceKind -eq "file") {
            New-Item -ItemType Directory -Force -Path $extractDirectory | Out-Null
            Copy-Item -LiteralPath $archivePath -Destination (Join-Path $extractDirectory ([string]$source.archive)) -Force
        }
        elseif ($sourceKind -eq "archive") {
            Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
        }
        else {
            throw "Unsupported source kind '$sourceKind' for $($source.id)"
        }

        foreach ($mapping in $source.files) {
            $pattern = [string]$mapping.match
            $extractPrefix = $extractDirectory.TrimEnd("\") + "\"
            $matches = @(
                Get-ChildItem -LiteralPath $extractDirectory -Recurse -File | Where-Object {
                    $relative = $_.FullName.Substring($extractPrefix.Length).Replace("\", "/")
                    $relative -match $pattern
                }
            )
            if ($matches.Count -ne 1) {
                throw "Expected exactly one '$pattern' in $($source.archive), found $($matches.Count)"
            }

            $targetName = [string]$mapping.target
            $targetPath = Join-Path $stagingDirectory $targetName
            $targetParent = Split-Path -Parent $targetPath
            New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
            Copy-Item -LiteralPath $matches[0].FullName -Destination $targetPath -Force
            # Later sources intentionally overlay files from earlier sources
            # (for example runetfreedom geoip/geosite over Xray defaults).
            # Keep one manifest entry for the final staged owner and hash.
            $manifestFilesByName[$targetName] = [ordered]@{
                name = $targetName
                source = [string]$source.id
                version = [string]$source.version
                sha256 = Get-Sha256 $targetPath
            }
        }
    }

    # Build our thin relay against the exact official module. Neither the
    # installed app nor a resumed release resolves moving upstream versions.
    $amnezia = $lock.amnezia
    $sdkSource = [pscustomobject]@{
        id = "go-sdk"; version = $amnezia.toolchain.version
        archive = $amnezia.toolchain.archive; sha256 = $amnezia.toolchain.sha256
        url = $amnezia.toolchain.url
    }
    $sdkArchive = Get-VerifiedArchive $sdkSource $DownloadCache
    $sdkDirectory = Join-Path $temporaryRoot "go-sdk"
    Expand-Archive -LiteralPath $sdkArchive -DestinationPath $sdkDirectory -Force
    $go = Join-Path $sdkDirectory "go\bin\go.exe"
    $savedEnvironment = @{}
    foreach ($key in @("GOTOOLCHAIN", "GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED", "GOCACHE", "GOMODCACHE", "AMNEZIA_TEST_SINGBOX")) {
        $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
    }
    Push-Location (Join-Path $repoRoot "runtime\amnezia")
    try {
        $env:GOTOOLCHAIN = "local"
        $env:GOFLAGS = ""
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"
        $env:GOCACHE = Join-Path $DownloadCache "go-build"
        $env:GOMODCACHE = Join-Path $DownloadCache "go-modules"
        $env:AMNEZIA_TEST_SINGBOX = Join-Path $stagingDirectory "sing-box.exe"
        $python = Join-Path $repoRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
            throw "Project Python is required to build the patched sing-box front"
        }
        & $python (Join-Path $PSScriptRoot "build_singbox_front.py") --lock $LockFile `
            --output $env:AMNEZIA_TEST_SINGBOX --work (Join-Path $temporaryRoot "singbox-source") --go $go
        if ($LASTEXITCODE -ne 0) { throw "Patched sing-box build/tests failed; no binary fallback allowed" }
        $singboxBuild = Get-Content -Raw -LiteralPath (Join-Path $stagingDirectory "sing-box.build.json") | ConvertFrom-Json
        foreach ($name in @("sing-box.exe", "sing-box.build.json")) {
            $manifestFilesByName[$name] = [ordered]@{
                name = $name; source = "sing-box-extended"; version = [string]$lock.singbox_build.version
                sha256 = Get-Sha256 (Join-Path $stagingDirectory $name)
            }
        }
        if (-not (Test-Path -LiteralPath $env:AMNEZIA_TEST_SINGBOX -PathType Leaf)) {
            throw "Locked sing-box is required for the Amnezia transport integration gate"
        }
        $modulePin = "$($amnezia.module)@$($amnezia.version)"
        $moduleText = (& $go mod download -json $modulePin | Out-String)
        if ($LASTEXITCODE -ne 0) { throw "Official Amnezia module download failed" }
        $module = $moduleText | ConvertFrom-Json
        if ([string]$module.Origin.Hash -ne [string]$amnezia.commit -or
            [string]$module.Sum -ne [string]$amnezia.module_sum -or
            [string]$module.GoModSum -ne [string]$amnezia.module_go_mod_sum -or
            (Get-Sha256 ([string]$module.Zip)) -ne [string]$amnezia.sha256) {
            throw "Official Amnezia module provenance mismatch"
        }
        $selectedVersion = (& $go list -m -f '{{.Version}}' ([string]$amnezia.module) | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $selectedVersion -ne [string]$amnezia.version) {
            throw "Amnezia go.mod and release lock differ"
        }
        & $go test -mod=readonly ./...
        if ($LASTEXITCODE -ne 0) { throw "Amnezia Windows transport tests failed" }
        $relayPath = Join-Path $stagingDirectory "zapret-amnezia.exe"
        & $go build -mod=readonly -trimpath -buildvcs=false '-ldflags=-s -w' -o $relayPath .
        if ($LASTEXITCODE -ne 0) { throw "Amnezia Windows transport build failed" }
        Copy-Item -LiteralPath (Join-Path ([string]$module.Dir) "LICENSE") -Destination (Join-Path $stagingDirectory "LICENSE-Amnezia.txt")
        foreach ($name in @("zapret-amnezia.exe", "LICENSE-Amnezia.txt")) {
            $manifestFilesByName[$name] = [ordered]@{
                name = $name; source = "amnezia"; version = [string]$amnezia.version
                sha256 = Get-Sha256 (Join-Path $stagingDirectory $name)
            }
        }
    }
    finally {
        Pop-Location
        foreach ($key in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], "Process")
        }
    }
    $manifest = [ordered]@{
        schema = 1
        platform = "windows-x64"
        generated_at_utc = [DateTime]::UtcNow.ToString("o")
        lock_sha256 = Get-Sha256 $LockFile
        inputs_sha256 = $inputHash
        singbox_build = $singboxBuild
        sources = (@($lock.sources) + @($amnezia)) | ForEach-Object {
            $repository = if ($_.PSObject.Properties.Name -contains "repository") { [string]$_.repository } else { "" }
            $channel = if ($_.PSObject.Properties.Name -contains "channel") { [string]$_.channel } else { "" }
            $releasePrerelease = if ($_.PSObject.Properties.Name -contains "release_prerelease") { [bool]$_.release_prerelease } else { $false }
            [ordered]@{
                id = [string]$_.id
                version = [string]$_.version
                archive_sha256 = [string]$_.sha256
                url = [string]$_.url
                repository = $repository
                channel = $channel
                release_prerelease = $releasePrerelease
            }
        }
        files = @($manifestFilesByName.Values)
    }
    $manifestPath = Join-Path $stagingDirectory "core-manifest.windows-x64.json"
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    Remove-Item -LiteralPath $partialOutputArchive -Force -ErrorAction SilentlyContinue
    $sevenZipArguments = @(
        "a", "-t7z", "-mx=7", "-y",
        $partialOutputArchive,
        (Join-Path $stagingDirectory "*")
    )
    $sevenZipProcess = Start-Process -FilePath $sevenZipPath -ArgumentList $sevenZipArguments `
        -NoNewWindow -Wait -PassThru
    if ($sevenZipProcess.ExitCode -ne 0) {
        throw "7z failed with exit code $($sevenZipProcess.ExitCode)"
    }
    $testProcess = Start-Process -FilePath $sevenZipPath -ArgumentList @("t", "-y", $partialOutputArchive) `
        -NoNewWindow -Wait -PassThru
    if ($testProcess.ExitCode -ne 0) {
        throw "7z verification failed with exit code $($testProcess.ExitCode)"
    }
    Move-Item -LiteralPath $partialOutputArchive -Destination $OutputArchive -Force
    $lockHash = Get-Sha256 $LockFile
    [System.IO.File]::WriteAllText(
        "$OutputArchive.lock.sha256",
        "$lockHash`n",
        [System.Text.Encoding]::ASCII
    )
    [System.IO.File]::WriteAllText("$OutputArchive.inputs.sha256", "$inputHash`n", [System.Text.Encoding]::ASCII)
    Write-Host "[core] bundle ready: $OutputArchive"
    Write-Host "[core] SHA-256: $(Get-Sha256 $OutputArchive)"
}
finally {
    Remove-Item -LiteralPath $partialOutputArchive -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
