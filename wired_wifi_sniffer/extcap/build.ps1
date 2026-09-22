#requires -Version 5
# Builds the ESP32 WiFi Sniffer extcap binary.
# Usage: ./build.ps1            # build esp32wifi.exe for this machine
#        ./build.ps1 -Install   # build, then copy into Wireshark's personal extcap dir

param(
    [switch]$Install
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go toolchain not found. Install it from https://go.dev/dl/ and re-run."
}

$out = "esp32wifi.exe"
Write-Host "Building $out ..."
& go build -o $out .
Write-Host "Built $((Get-Item $out).FullName)"

if ($Install) {
    $dir = Join-Path $env:APPDATA "Wireshark\extcap"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -Force $out (Join-Path $dir $out)
    Write-Host "Installed to $dir"
    Write-Host "Restart Wireshark or press F5 (Refresh Interfaces)."
}
