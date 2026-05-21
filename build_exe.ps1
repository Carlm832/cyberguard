$ErrorActionPreference = "Stop"

$iconPath = Join-Path $PSScriptRoot "assets\app_icon.ico"
$versionFile = Join-Path $PSScriptRoot "version_info.txt"

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Exe,
    [string[]] $Args
  )
  Write-Host ">> $Exe $($Args -join ' ')"

  # Native tools often write informational logs to stderr; don't treat those as
  # PowerShell exceptions. We fail only on non-zero exit code.
  $previous = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  & $Exe @Args
  $ErrorActionPreference = $previous

  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')"
  }
}

$pyVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) {
  throw "Unable to detect Python version."
}
if ([version]$pyVersion -ge [version]"3.13") {
  throw "Detected Python $pyVersion. This build currently requires Python 3.12 (or 3.11) because pywebview dependencies fail on 3.13+ in this setup."
}

Write-Host "Installing build dependencies..."
Invoke-Step -Exe "python" -Args @("-m", "pip", "install", "--upgrade", "pip")
Invoke-Step -Exe "python" -Args @("-m", "pip", "install", "pyinstaller", "-r", "requirements.txt")

Write-Host "Building CyberGuard executable..."
$pyinstallerArgs = @(
  "--noconfirm",
  "--clean",
  "--onefile",
  "--windowed",
  "--name", "CyberGuard",
  "--add-data", "templates;templates",
  "--add-data", "public;public",
  "--version-file", $versionFile
)

if (Test-Path $iconPath) {
  Write-Host "Using icon: $iconPath"
  $pyinstallerArgs += @("--icon", $iconPath)
} else {
  Write-Host "No icon found at assets\\app_icon.ico (using default app icon)."
}

$pyinstallerCallArgs = @("-m", "PyInstaller") + $pyinstallerArgs + @("run_cyberguard.py")
Invoke-Step -Exe "python" -Args $pyinstallerCallArgs

Write-Host ""
Write-Host "Build complete: dist\\CyberGuard.exe"
