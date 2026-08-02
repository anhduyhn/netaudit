# Build a standalone netauditor.exe (no Python needed on the target machine).
# Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1
# Output: dist\netauditor.exe
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path ".venv")) { python -m venv .venv }
& .venv\Scripts\python -m pip install --quiet --upgrade pip
& .venv\Scripts\python -m pip install --quiet . pyinstaller

& .venv\Scripts\pyinstaller --onefile --console --clean --noconfirm `
    --name netauditor packaging\entry.py

Write-Host "`nBuilt: dist\netauditor.exe"
& dist\netauditor.exe --version
