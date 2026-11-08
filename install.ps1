param(
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
Write-Host "=== HiveBreach Installer (Windows) ===" -ForegroundColor Cyan

# Check Python 3.10+
try {
    $pyVersion = & python --version 2>&1
    Write-Host "Found: $pyVersion" -ForegroundColor Green
    if ($pyVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Host "ERROR: Python 3.10+ required, got $major.$minor" -ForegroundColor Red
            exit 1
        }
    }
} catch {
    Write-Host "ERROR: Python not found. Install Python 3.10+ first." -ForegroundColor Red
    exit 1
}

# Create virtual environment
if (-not (Test-Path -LiteralPath ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    & python -m venv .venv
}

# Activate and install deps
Write-Host "Installing dependencies..." -ForegroundColor Yellow
& ".venv\Scripts\pip" install --upgrade pip
& ".venv\Scripts\pip" install -e .

# Copy .env.example to .env if not exists
if (-not (Test-Path -LiteralPath $EnvFile)) {
    if (Test-Path -LiteralPath ".env.example") {
        Copy-Item -LiteralPath ".env.example" -Destination $EnvFile
        Write-Host "Created $EnvFile from .env.example" -ForegroundColor Green
    }
} else {
    Write-Host "$EnvFile already exists, skipping" -ForegroundColor Yellow
}

# Create sessions directory
if (-not (Test-Path -LiteralPath "sessions")) {
    New-Item -ItemType Directory -Path "sessions" | Out-Null
    Write-Host "Created sessions/ directory" -ForegroundColor Green
}

Write-Host "=== Install complete ===" -ForegroundColor Cyan
Write-Host "Activate: .venv\Scripts\Activate.ps1"
