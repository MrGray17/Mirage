[CmdletBinding()]
param(
    [string]$Distribution = "Ubuntu",
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$installRoot = Join-Path $env:LOCALAPPDATA "Mirage"
$windowsBin = Join-Path $installRoot "bin"
$frontend = Join-Path $windowsBin "mirage.exe"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mirage-install-" + [Guid]::NewGuid().ToString("N"))
$temporaryWindows = Join-Path $temporaryRoot "mirage.exe"
$temporaryLinux = Join-Path $temporaryRoot "mirage-linux-amd64"

function Invoke-WSLExact {
    param([string[]]$Arguments)
    & wsl.exe -d $Distribution --exec @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed with exit code $LASTEXITCODE"
    }
}

try {
    if (-not (Get-Command go.exe -ErrorAction SilentlyContinue)) {
        throw "Go 1.24 or newer is required to install MIRAGE from source."
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
    $distributions = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Trim([char]0).Trim() } | Where-Object { $_ }
    if ($Distribution -notin $distributions) {
        throw "WSL distribution '$Distribution' was not found. No distribution was installed automatically."
    }

    New-Item -ItemType Directory -Force -Path $temporaryRoot, $windowsBin | Out-Null
    $ldflags = "-X github.com/MrGray17/Mirage/internal/buildinfo.Version=$Version -X github.com/MrGray17/Mirage/internal/buildinfo.Commit=$commit"

    & go.exe -C $repoRoot build -ldflags $ldflags -o $temporaryWindows ./cmd/mirage
    if ($LASTEXITCODE -ne 0) { throw "Windows frontend build failed." }
    $oldGOOS = $env:GOOS
    $oldGOARCH = $env:GOARCH
    try {
        $env:GOOS = "linux"
        $env:GOARCH = "amd64"
        & go.exe -C $repoRoot build -ldflags $ldflags -o $temporaryLinux ./cmd/mirage
        if ($LASTEXITCODE -ne 0) { throw "Linux backend build failed." }
    }
    finally {
        $env:GOOS = $oldGOOS
        $env:GOARCH = $oldGOARCH
    }

    Copy-Item -LiteralPath $temporaryWindows -Destination $frontend -Force
    $linuxHome = (& wsl.exe -d $Distribution --exec printenv HOME).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $linuxHome.StartsWith("/")) {
        throw "Could not establish the selected WSL user's home directory."
    }
    $backendDir = "$linuxHome/.local/share/mirage/bin"
    $backend = "$backendDir/mirage"
    $linuxSource = (& wsl.exe -d $Distribution --exec wslpath -a -u $temporaryLinux).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $linuxSource.StartsWith("/")) {
        throw "Could not translate the Linux backend artifact path."
    }
    Invoke-WSLExact -Arguments @("mkdir", "-p", "--", $backendDir)
    Invoke-WSLExact -Arguments @("install", "-m", "0755", $linuxSource, $backend)

    $config = [ordered]@{ wsl_distribution = $Distribution; backend = $backend }
    $configPath = Join-Path $installRoot "config.json"
    [System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($userPath -split ";" | Where-Object { $_ })
    if ($windowsBin -notin $parts) {
        [Environment]::SetEnvironmentVariable("Path", (($parts + $windowsBin) -join ";"), "User")
    }
    Write-Host "Installed MIRAGE frontend: $frontend"
    Write-Host "Installed MIRAGE WSL backend: $Distribution`:$backend"
    Write-Host "Open a new PowerShell window, then run: mirage setup"
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
