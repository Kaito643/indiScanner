#!/usr/bin/env pwsh
# ThreatHarvester launcher.
#
# Sets up the toolchain PATH (cargo + mingw linker), builds a release binary the
# first time, then forwards all arguments to it. After the one-time build every
# launch is instant. With no arguments it opens the interactive TUI.
#
#   .\th.ps1                    # launch the TUI
#   .\th.ps1 serve              # start the web dashboard
#   .\th.ps1 enrich 1.2.3.4     # any CLI subcommand
#   .\th.ps1 -Build enrich ...  # force a rebuild first (after code changes)

param([switch]$Build)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$exe = Join-Path $root 'target\release\threatharvester.exe'

# The mingw linker and cargo are only needed to BUILD; prepend them for that step.
$env:Path = "$env:USERPROFILE\.cargo\bin;C:\ProgramData\mingw64\mingw64\bin;$env:Path"

if ($Build -or -not (Test-Path $exe)) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Error "cargo not found. Install Rust from https://rustup.rs/ first."
        exit 1
    }
    Write-Host "Building ThreatHarvester (release) - first run only, this takes a few minutes..." -ForegroundColor Cyan
    Push-Location $root
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }
    } finally {
        Pop-Location
    }
}

# No subcommand -> open the interactive terminal UI. Splat the real $args array
# directly; routing it through a variable can unwrap a single arg into a string.
if ($args.Count -eq 0) {
    & $exe tui
} else {
    & $exe @args
}
exit $LASTEXITCODE
