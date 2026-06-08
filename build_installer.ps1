$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$distDir = Join-Path $root "dist"
$stagingDir = Join-Path $distDir "installer-staging"
$sedPath = Join-Path $distDir "CyberGuardSetup.sed"
$setupPath = Join-Path $distDir "CyberGuardSetup.exe"
$exePath = Join-Path $distDir "CyberGuard.exe"
$envPath = Join-Path $distDir ".env"
$iconPath = Join-Path $root "assets\app_icon.ico"
$installScriptPath = Join-Path $root "installer\install.ps1"
$iexpressPath = Join-Path $env:WINDIR "System32\iexpress.exe"
$venvScripts = Join-Path $root ".venv312\Scripts"

function Invoke-Step {
  param(
    [Parameter(Mandatory = $true)]
    [string] $Exe,
    [string[]] $Args
  )
  Write-Host ">> $Exe $($Args -join ' ')"
  & $Exe @Args
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')"
  }
}

if (-not (Test-Path $iexpressPath)) {
  throw "IExpress was not found at $iexpressPath."
}

if (Test-Path (Join-Path $venvScripts "python.exe")) {
  $env:PATH = "$venvScripts;$env:PATH"
}

if (-not (Test-Path $exePath)) {
  Write-Host "CyberGuard.exe not found. Building executable first..."
  Invoke-Step -Exe "powershell.exe" -Args @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $root "build_exe.ps1"))
}

if (-not (Test-Path $exePath)) {
  throw "Expected executable was not produced: $exePath"
}
if (-not (Test-Path $installScriptPath)) {
  throw "Installer script missing: $installScriptPath"
}

if (Test-Path $stagingDir) {
  Remove-Item -LiteralPath $stagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

Copy-Item -LiteralPath $exePath -Destination (Join-Path $stagingDir "CyberGuard.exe") -Force
Copy-Item -LiteralPath $installScriptPath -Destination (Join-Path $stagingDir "install.ps1") -Force
if (Test-Path $envPath) {
  Copy-Item -LiteralPath $envPath -Destination (Join-Path $stagingDir ".env") -Force
}
if (Test-Path $iconPath) {
  Copy-Item -LiteralPath $iconPath -Destination (Join-Path $stagingDir "app_icon.ico") -Force
}

$targetName = $setupPath
$sourceDir = $stagingDir + "\"

$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=<None>
AdminQuietInstCmd=%AppLaunched%
UserQuietInstCmd=%AppLaunched%
SourceFiles=SourceFiles

[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=CyberGuard has been installed.
TargetName=$targetName
FriendlyName=CyberGuard Setup
AppLaunched=powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
FILE0=CyberGuard.exe
FILE1=install.ps1
FILE2=.env
FILE3=app_icon.ico

[SourceFiles]
SourceFiles0=$sourceDir

[SourceFiles0]
%FILE0%=
%FILE1%=
%FILE2%=
%FILE3%=
"@

Set-Content -LiteralPath $sedPath -Value $sed -Encoding ASCII -Force

if (Test-Path $setupPath) {
  Remove-Item -LiteralPath $setupPath -Force
}

Invoke-Step -Exe $iexpressPath -Args @("/N", "/Q", $sedPath)

if (-not (Test-Path $setupPath)) {
  throw "Installer was not created: $setupPath"
}

Write-Host ""
Write-Host "Installer complete: dist\CyberGuardSetup.exe"
