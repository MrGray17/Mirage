[CmdletBinding()]
param(
    [string]$Distribution = "Ubuntu",
    [string]$Version = "1.0.0-dev"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$installRoot = Join-Path $env:LOCALAPPDATA "Mirage"
$windowsBin = Join-Path $installRoot "bin"
$frontend = Join-Path $windowsBin "mirage.exe"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mirage-install-" + [Guid]::NewGuid().ToString("N"))
$temporaryWindows = Join-Path $temporaryRoot "mirage.exe"
$temporaryLinux = Join-Path $temporaryRoot "mirage-linux-amd64"
$transactionId = [Guid]::NewGuid().ToString("N")
$windowsStage = Join-Path $windowsBin (".mirage-stage-$transactionId.exe")
$windowsBackup = Join-Path $windowsBin (".mirage-backup-$transactionId.exe")
$configPath = Join-Path $installRoot "config.json"
$configStage = Join-Path $installRoot (".config-stage-$transactionId.json")
$configBackup = Join-Path $installRoot (".config-backup-$transactionId.json")
$backendDir = $null
$backend = $null
$linuxStage = $null
$linuxBackup = $null
$commitStarted = $false
$transactionComplete = $false
$preserveRecoveryFiles = $false
$hadFrontend = $false
$hadBackend = $false
$hadConfig = $false
$pathChanged = $false
$originalUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

function Invoke-WSLExact {
    param([string[]]$Arguments)
    & wsl.exe -d $Distribution --exec @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE"
    }
}

function Get-MirageBuildInfo {
    param(
        [string]$WindowsBinary,
        [string]$LinuxBinary,
        [string]$TargetDistribution
    )

    $windowsOutput = & $WindowsBinary version --json
    $windowsExitCode = $LASTEXITCODE
    if ($windowsExitCode -ne 0) {
        throw "Windows frontend version probe failed with exit code $windowsExitCode."
    }
    $windowsJson = ($windowsOutput -join [Environment]::NewLine).Trim()
    $windowsInfo = $windowsJson | ConvertFrom-Json

    $linuxOutput = & wsl.exe -d $TargetDistribution --exec $LinuxBinary version --json
    $linuxExitCode = $LASTEXITCODE
    if ($linuxExitCode -ne 0) {
        throw "Linux backend version probe failed with exit code $linuxExitCode."
    }
    $linuxJson = ($linuxOutput -join [Environment]::NewLine).Trim()
    $linuxInfo = $linuxJson | ConvertFrom-Json

    return @{ Windows = $windowsInfo; Linux = $linuxInfo }
}

function Assert-MirageBuildPair {
    param(
        [string]$WindowsBinary,
        [string]$LinuxBinary,
        [string]$TargetDistribution,
        [string]$ExpectedVersion,
        [string]$ExpectedCommit
    )

    $info = Get-MirageBuildInfo -WindowsBinary $WindowsBinary -LinuxBinary $LinuxBinary -TargetDistribution $TargetDistribution
    $windowsInfo = $info.Windows
    $linuxInfo = $info.Linux

    if ([string]$windowsInfo.version -ne $ExpectedVersion -or
        [string]$linuxInfo.version -ne $ExpectedVersion -or
        [string]$windowsInfo.commit -ne $ExpectedCommit -or
        [string]$linuxInfo.commit -ne $ExpectedCommit -or
        [string]$windowsInfo.platform -ne "windows" -or
        [string]$linuxInfo.platform -ne "linux" -or
        [int]$windowsInfo.bridge_protocol -lt 1 -or
        [int]$windowsInfo.bridge_protocol -ne [int]$linuxInfo.bridge_protocol) {
        throw "MIRAGE frontend and backend disagree on version, commit identity, platform, or bridge protocol."
    }
}

try {
    if (-not (Get-Command go.exe -ErrorAction SilentlyContinue)) {
        throw "Go 1.27.3 or newer is required to install MIRAGE from source."
    }
    $goVersionOutput = & go.exe version
    if ($LASTEXITCODE -ne 0 -or (($goVersionOutput -join " ") -notmatch 'go(\d+\.\d+(?:\.\d+)?)')) {
        throw "Could not establish the installed Go toolchain version."
    }
    $goVersion = [version]$Matches[1]
    if ($goVersion -lt [version]"1.27.3") {
        throw "Go 1.27.3 or newer is required; found Go $goVersion."
    }
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw "Git is required to establish MIRAGE's source commit identity. No installed files were changed."
    }
    $observedCommit = @(& git.exe -C $repoRoot rev-parse --verify HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or $observedCommit.Count -ne 1) {
        throw "Could not establish MIRAGE's source commit identity. No installed files were changed."
    }
    $commit = $observedCommit[0].Trim()
    if ($commit -cnotmatch '^[0-9a-f]{40}$') {
        throw "MIRAGE source commit identity is not a canonical SHA-1. No installed files were changed."
    }
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        throw "WSL2 is required. Install it explicitly, then rerun this installer."
    }
    $distributionOutput = @(& wsl.exe --list --quiet)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not enumerate installed WSL distributions."
    }
    $distributions = $distributionOutput | ForEach-Object { $_.Trim([char]0).Trim() } | Where-Object { $_ }
    if ($Distribution -notin $distributions) {
        throw "WSL distribution '$Distribution' was not found. No distribution was installed automatically."
    }

    New-Item -ItemType Directory -Force -Path $temporaryRoot, $windowsBin, $installRoot | Out-Null
    $ldflags = "-X github.com/MrGray17/Mirage/internal/buildinfo.Version=$Version -X github.com/MrGray17/Mirage/internal/buildinfo.Commit=$commit"

    $oldGOOS = $env:GOOS
    $oldGOARCH = $env:GOARCH
    try {
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        & go.exe -C $repoRoot build -ldflags $ldflags -o $temporaryWindows ./cmd/mirage
        if ($LASTEXITCODE -ne 0) { throw "Windows frontend build failed." }

        $env:GOOS = "linux"
        $env:GOARCH = "amd64"
        & go.exe -C $repoRoot build -ldflags $ldflags -o $temporaryLinux ./cmd/mirage
        if ($LASTEXITCODE -ne 0) { throw "Linux backend build failed." }
    }
    finally {
        $env:GOOS = $oldGOOS
        $env:GOARCH = $oldGOARCH
    }

    $linuxHomeOutput = & wsl.exe -d $Distribution --exec printenv HOME
    if ($LASTEXITCODE -ne 0) {
        throw "Could not establish the selected WSL user's home directory."
    }
    $linuxHome = ($linuxHomeOutput -join [Environment]::NewLine).Trim()
    if (-not $linuxHome.StartsWith("/")) {
        throw "WSL returned an invalid home directory."
    }
    $backendDir = "$linuxHome/.local/share/mirage/bin"
    $backend = "$backendDir/mirage"
    $linuxSourceOutput = & wsl.exe -d $Distribution --exec wslpath -a -u $temporaryLinux
    if ($LASTEXITCODE -ne 0) {
        throw "Could not translate the Linux backend artifact path."
    }
    $linuxSource = ($linuxSourceOutput -join [Environment]::NewLine).Trim()
    if (-not $linuxSource.StartsWith("/")) {
        throw "WSL returned an invalid path for the staged Linux backend."
    }
    $linuxStage = "$backendDir/.mirage-stage-$transactionId"
    $linuxBackup = "$backendDir/.mirage-backup-$transactionId"

    Invoke-WSLExact -Arguments @("mkdir", "-p", "--", $backendDir)
    Copy-Item -LiteralPath $temporaryWindows -Destination $windowsStage
    Invoke-WSLExact -Arguments @("install", "-m", "0755", $linuxSource, $linuxStage)

    $config = [ordered]@{ wsl_distribution = $Distribution; backend = $backend }
    [System.IO.File]::WriteAllText($configStage, ($config | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))

    # Reject a mismatched or unexecutable binary pair before replacing the
    # currently installed frontend, backend, or bridge configuration.
    Assert-MirageBuildPair -WindowsBinary $windowsStage -LinuxBinary $linuxStage -TargetDistribution $Distribution -ExpectedVersion $Version -ExpectedCommit $commit

    if (Test-Path -LiteralPath $frontend) {
        if (-not (Test-Path -LiteralPath $frontend -PathType Leaf)) {
            throw "The existing frontend path is not a regular file; refusing to overwrite it."
        }
        Copy-Item -LiteralPath $frontend -Destination $windowsBackup
        $hadFrontend = $true
    }
    if (Test-Path -LiteralPath $configPath) {
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            throw "The existing config path is not a regular file; refusing to overwrite it."
        }
        Copy-Item -LiteralPath $configPath -Destination $configBackup
        $hadConfig = $true
    }

    & wsl.exe -d $Distribution --exec test -L $backend
    $backendLinkExitCode = $LASTEXITCODE
    if ($backendLinkExitCode -eq 0) {
        throw "The existing Linux backend is a symbolic link; refusing to overwrite it."
    }
    if ($backendLinkExitCode -ne 1) {
        throw "Could not safely inspect the existing Linux backend path."
    }
    & wsl.exe -d $Distribution --exec test -e $backend
    $backendExistsExitCode = $LASTEXITCODE
    if ($backendExistsExitCode -eq 0) {
        & wsl.exe -d $Distribution --exec test -f $backend
        $backendFileExitCode = $LASTEXITCODE
        if ($backendFileExitCode -ne 0) {
            throw "The existing Linux backend is not a regular file; refusing to overwrite it."
        }
        Invoke-WSLExact -Arguments @("cp", "-p", "--", $backend, $linuxBackup)
        $hadBackend = $true
    }
    elseif ($backendExistsExitCode -ne 1) {
        throw "Could not safely inspect the existing Linux backend path."
    }

    # A failed switch or failed live bridge smoke test restores all prior files.
    $commitStarted = $true
    Invoke-WSLExact -Arguments @("mv", "-f", "--", $linuxStage, $backend)
    Move-Item -LiteralPath $windowsStage -Destination $frontend -Force
    Move-Item -LiteralPath $configStage -Destination $configPath -Force

    Assert-MirageBuildPair -WindowsBinary $frontend -LinuxBinary $backend -TargetDistribution $Distribution -ExpectedVersion $Version -ExpectedCommit $commit

    # setup --help exercises the installed Windows-to-WSL bridge and the
    # backend version handshake, then exits before touching Docker or models.
    $smokeOutput = & $frontend setup --help 2>&1
    $smokeExitCode = $LASTEXITCODE
    if ($smokeExitCode -ne 0) {
        throw "Post-install Windows-to-WSL bridge check failed: $(($smokeOutput -join ' ').Trim())"
    }

    $parts = @($originalUserPath -split ";" | Where-Object { $_ })
    if ($windowsBin -notin $parts) {
        $pathChanged = $true
        [Environment]::SetEnvironmentVariable("Path", (($parts + $windowsBin) -join ";"), "User")
    }
    $transactionComplete = $true
}
catch {
    $failureMessage = $_.Exception.Message
    if (-not $commitStarted) {
        throw "MIRAGE installation failed before changing installed files: $failureMessage"
    }

    $rollbackErrors = @()
    try {
        if ($hadBackend) {
            Invoke-WSLExact -Arguments @("mv", "-f", "--", $linuxBackup, $backend)
        }
        else {
            Invoke-WSLExact -Arguments @("rm", "-f", "--", $backend)
        }
    }
    catch { $rollbackErrors += "Linux backend: $($_.Exception.Message)" }

    try {
        if ($hadFrontend) {
            Copy-Item -LiteralPath $windowsBackup -Destination $frontend -Force
        }
        elseif (Test-Path -LiteralPath $frontend) {
            Remove-Item -LiteralPath $frontend -Force
        }
    }
    catch { $rollbackErrors += "Windows frontend: $($_.Exception.Message)" }

    try {
        if ($hadConfig) {
            Copy-Item -LiteralPath $configBackup -Destination $configPath -Force
        }
        elseif (Test-Path -LiteralPath $configPath) {
            Remove-Item -LiteralPath $configPath -Force
        }
    }
    catch { $rollbackErrors += "bridge config: $($_.Exception.Message)" }

    if ($pathChanged) {
        try { [Environment]::SetEnvironmentVariable("Path", $originalUserPath, "User") }
        catch { $rollbackErrors += "user PATH: $($_.Exception.Message)" }
    }

    if ($rollbackErrors.Count -gt 0) {
        $preserveRecoveryFiles = $true
        throw "MIRAGE installation failed: $failureMessage. Automatic rollback was incomplete: $($rollbackErrors -join '; '). Recovery copies were retained under $installRoot and $backendDir."
    }
    throw "MIRAGE installation failed: $failureMessage. The previous installation was restored."
}
finally {
    if ($linuxStage) {
        try { Invoke-WSLExact -Arguments @("rm", "-f", "--", $linuxStage) } catch { }
    }
    foreach ($path in @($windowsStage, $configStage)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $preserveRecoveryFiles) {
        foreach ($path in @($windowsBackup, $configBackup)) {
            if ($path -and (Test-Path -LiteralPath $path)) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
        if ($linuxBackup) {
            try { Invoke-WSLExact -Arguments @("rm", "-f", "--", $linuxBackup) } catch { }
        }
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($transactionComplete) {
    Write-Host "Installed MIRAGE frontend: $frontend"
    Write-Host ("Installed MIRAGE WSL backend: {0}:{1}" -f $Distribution, $backend)
    Write-Host "Install validation passed: build identity and Windows-to-WSL protocol match."
    Write-Host "Open a new PowerShell window, then run: mirage setup"
}
