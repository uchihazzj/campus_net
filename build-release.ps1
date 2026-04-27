# Build script for Campus Net Client (Windows MSVC)
# Requires: Visual Studio 2022 Build Tools with "C++ build tools" workload

param(
    [switch]$Check,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Locate vcvars64.bat
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $vcvars)) {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
}
if (-not (Test-Path $vcvars)) {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
}

if (-not (Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found. Please install Visual Studio 2022 Build Tools with 'C++ build tools' workload."
    exit 1
}

Write-Host "Using: $vcvars" -ForegroundColor Cyan

# Ensure rustup/cargo are available
$rustup = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustup) {
    $cargoHome = "$env:USERPROFILE\.cargo\bin"
    if (Test-Path "$cargoHome\rustup.exe") {
        $env:Path = "$cargoHome;$env:Path"
    } else {
        Write-Error "rustup not found. Please install Rust from https://rustup.rs/"
        exit 1
    }
}

# Verify MSVC toolchain
$toolchain = rustup default 2>&1
Write-Host "Toolchain: $toolchain" -ForegroundColor Cyan

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force target -ErrorAction SilentlyContinue
}

# Build command
$cargoArgs = @("build", "--release")
if ($Check) {
    $cargoArgs = @("check", "--release")
}

$cmd = "cmd /c `"`"$vcvars`" && cd /d `"$PSScriptRoot`" && cargo $cargoArgs`""

Write-Host "Building..." -ForegroundColor Cyan
Invoke-Expression $cmd

if ($LASTEXITCODE -eq 0) {
    if (-not $Check) {
        $exePath = "$PSScriptRoot\target\release\campus-net-client.exe"
        if (Test-Path $exePath) {
            $size = (Get-Item $exePath).Length / 1MB
            Write-Host "Build successful!" -ForegroundColor Green
            Write-Host "  $exePath" -ForegroundColor Green
            Write-Host "  Size: $([math]::Round($size, 2)) MB" -ForegroundColor Green
        }
    } else {
        Write-Host "Check passed!" -ForegroundColor Green
    }
} else {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
