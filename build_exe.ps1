$ErrorActionPreference = "Stop"

Write-Host "Installing build dependencies..."
python -m pip install --upgrade pip
python -m pip install pyinstaller -r requirements.txt

Write-Host "Building CyberGuard executable..."
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --name CyberGuard `
  --add-data "templates;templates" `
  --add-data "public;public" `
  run_cyberguard.py

Write-Host ""
Write-Host "Build complete: dist\\CyberGuard.exe"
