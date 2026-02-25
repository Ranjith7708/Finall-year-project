<#
Run development server and smoke-test the app.

Features:
- Creates a virtualenv at `.venv` if missing
- Installs `requirements.txt` (falls back to minimal packages if network fails)
- Starts the Flask app in background
- Waits for `/health` to respond, opens browser
- Generates a tiny test image and POSTs it to `/analyze` (quick smoke test)

Usage (PowerShell, run from project root):
  .\run_dev.ps1
#>

Set-StrictMode -Version Latest
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $root

Write-Host "Working directory: $root"

if (-not (Test-Path -Path ".venv")) {
    Write-Host "Creating virtual environment .venv..."
    python -m venv .venv
}

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Python executable not found at $python. Make sure Python is on PATH and venv was created."; exit 1
}

& $python -m pip install --upgrade pip

# Try installing full requirements, fall back to minimal if network fails
try {
    Write-Host "Installing requirements from requirements.txt..."
    & $python -m pip install -r (Join-Path $root 'requirements.txt') -q
} catch {
    Write-Warning "Full install failed (network?). Installing minimal packages so app can run."
    & $python -m pip install flask Werkzeug -q
}

# Ensure static folders exist
New-Item -ItemType Directory -Force -Path .\static\uploads | Out-Null
New-Item -ItemType Directory -Force -Path .\static\results | Out-Null

Write-Host "Starting Flask app..."
# Start in new window so logs stay visible; capture PID
$proc = Start-Process -FilePath $python -ArgumentList (Join-Path $root 'app.py') -PassThru

# Wait for health endpoint
Write-Host "Waiting for server to respond on http://127.0.0.1:5000/health"
$max = 30
for ($i=0; $i -lt $max; $i++) {
    try {
        $r = Invoke-RestMethod -Uri 'http://127.0.0.1:5000/health' -TimeoutSec 2
        Write-Host "Server ready:`n" ($r | ConvertTo-Json -Depth 3)
        Start-Sleep -Milliseconds 500
        Start-Process 'http://127.0.0.1:5000'
        break
    } catch {
        Start-Sleep -Seconds 1
    }
    if ($i -eq $max-1) { Write-Error "Server did not respond within timeout."; exit 1 }
}

# Create a tiny test image (simple 100x100 PNG) without external deps
$testImage = Join-Path $root 'static\uploads\test_smoke.png'
try {
    # Try to use .NET System.Drawing to create a small PNG (Windows only)
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap 100,100
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::FromArgb(60,120,200))
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White)
    $g.DrawEllipse($pen,10,10,80,80)
    $bmp.Save($testImage, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "Generated test image at $testImage"
} catch {
    Write-Warning "Could not generate test image via System.Drawing; creating empty file instead."
    '' | Out-File -FilePath $testImage -Encoding ascii
}

Write-Host "Posting test image to /analyze (method=ORB)"
try {
    $form = @{ image = Get-Item $testImage; method = 'ORB' }
    $resp = Invoke-RestMethod -Uri 'http://127.0.0.1:5000/analyze' -Method Post -Form $form -TimeoutSec 30
    Write-Host "Analyze response:`n" ($resp | ConvertTo-Json -Depth 5)
} catch {
    Write-Warning "Analyze request failed: $_"
}

Pop-Location
