# Build a standalone netauditor.exe (no Python needed on the target machine).
# Run from the repo root:
#   powershell -ExecutionPolicy Bypass -File packaging\build-exe.ps1
# Output: dist\netauditor.exe
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

# Version the exe should end up reporting: whatever the working tree says.
$src = Get-Content netauditor\__init__.py -Raw
if ($src -notmatch '__version__\s*=\s*"([^"]+)"') { throw "could not read __version__" }
$expected = $Matches[1]
Write-Host "Building netauditor $expected from the working tree..."

# A running netauditor.exe locks the file: PyInstaller then quietly leaves the
# old binary in place and everything downstream looks mysteriously stale.
if (Test-Path "dist\netauditor.exe") {
    try {
        $fs = [System.IO.File]::Open((Resolve-Path "dist\netauditor.exe"), 'Open', 'Write')
        $fs.Close()
    } catch {
        throw "dist\netauditor.exe is locked - close the running netauditor before building."
    }
}

if (-not (Test-Path ".venv")) { python -m venv .venv }
& .venv\Scripts\python -m pip install --quiet --upgrade pip
# Dependencies only - the package itself is taken from the source tree below,
# so the exe can never lag behind uncommitted/just-bumped code. Any previously
# installed copy must go, or PyInstaller bundles that one instead.
& .venv\Scripts\python -m pip install --quiet -r requirements.txt pyinstaller
# pip warns on stderr when it was not installed; that is fine, not an error.
$ErrorActionPreference = "Continue"
& .venv\Scripts\python -m pip uninstall --quiet --yes netauditor 2>&1 | Out-Null
$ErrorActionPreference = "Stop"

# --paths . makes PyInstaller import netauditor from this working tree.
# --collect-all textual: it lazy-loads its widget modules, which static
# import analysis misses.
& .venv\Scripts\pyinstaller --onefile --console --clean --noconfirm `
    --paths . `
    --collect-all textual `
    --name netauditor packaging\entry.py

$built = (& dist\netauditor.exe --version) -replace '^netauditor\s+', ''
if ($built.Trim() -ne $expected) {
    throw "version mismatch: exe reports '$($built.Trim())' but the source says '$expected'"
}
Write-Host "`nBuilt: dist\netauditor.exe (netauditor $expected)"
