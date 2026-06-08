$ErrorActionPreference = "Stop"

$appName = "CyberGuard"
$publisher = "CyberGuard"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\CyberGuard"
$startMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\CyberGuard"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "CyberGuard.lnk"
$startMenuShortcut = Join-Path $startMenuDir "CyberGuard.lnk"
$uninstallShortcut = Join-Path $startMenuDir "Uninstall CyberGuard.lnk"
$sourceExe = Join-Path $PSScriptRoot "CyberGuard.exe"
$sourceEnv = Join-Path $PSScriptRoot ".env"
$sourceIcon = Join-Path $PSScriptRoot "app_icon.ico"
$targetExe = Join-Path $installDir "CyberGuard.exe"
$targetEnv = Join-Path $installDir ".env"
$targetIcon = Join-Path $installDir "app_icon.ico"
$uninstallScript = Join-Path $installDir "Uninstall-CyberGuard.ps1"

if (-not (Test-Path $sourceExe)) {
  throw "CyberGuard.exe was not found in the installer payload."
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null

Copy-Item -LiteralPath $sourceExe -Destination $targetExe -Force
if (Test-Path $sourceEnv) {
  Copy-Item -LiteralPath $sourceEnv -Destination $targetEnv -Force
}
if (Test-Path $sourceIcon) {
  Copy-Item -LiteralPath $sourceIcon -Destination $targetIcon -Force
}

$uninstallContent = @'
$ErrorActionPreference = "SilentlyContinue"

$appName = "CyberGuard"
$installDir = Join-Path $env:LOCALAPPDATA "Programs\CyberGuard"
$startMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\CyberGuard"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "CyberGuard.lnk"
$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CyberGuard"

Remove-Item -LiteralPath $desktopShortcut -Force
Remove-Item -LiteralPath $startMenuDir -Recurse -Force
Remove-Item -LiteralPath $installDir -Recurse -Force
Remove-Item -LiteralPath $uninstallKey -Recurse -Force
'@

Set-Content -LiteralPath $uninstallScript -Value $uninstallContent -Encoding UTF8 -Force

$shell = New-Object -ComObject WScript.Shell

$desktop = $shell.CreateShortcut($desktopShortcut)
$desktop.TargetPath = $targetExe
$desktop.WorkingDirectory = $installDir
$desktop.Description = "CyberGuard phishing and password security analyzer"
if (Test-Path $targetIcon) {
  $desktop.IconLocation = $targetIcon
}
$desktop.Save()

$start = $shell.CreateShortcut($startMenuShortcut)
$start.TargetPath = $targetExe
$start.WorkingDirectory = $installDir
$start.Description = "CyberGuard phishing and password security analyzer"
if (Test-Path $targetIcon) {
  $start.IconLocation = $targetIcon
}
$start.Save()

$uninstall = $shell.CreateShortcut($uninstallShortcut)
$uninstall.TargetPath = "powershell.exe"
$uninstall.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
$uninstall.WorkingDirectory = $installDir
$uninstall.Description = "Uninstall CyberGuard"
$uninstall.Save()

$uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CyberGuard"
New-Item -Path $uninstallKey -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayName" -Value $appName -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayVersion" -Value "1.0.0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "Publisher" -Value $publisher -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "InstallLocation" -Value $installDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "DisplayIcon" -Value $targetExe -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "UninstallString" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`"" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $uninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null

Start-Process -FilePath $targetExe -WorkingDirectory $installDir
