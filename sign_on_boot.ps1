$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"+"\pwsh-genshin-sign.lnk")
$objShortCut.TargetPath = (Get-Command "powerShell.exe").Source
$objShortCut.Arguments = "-WindowStyle Hidden $((Get-Item .\sign.ps1 | Resolve-Path).ProviderPath)"
$objShortCut.WorkingDirectory = "$(((Get-Item .\sign.ps1).Directory | Resolve-Path).ProviderPath)"
$objShortCut.Save()
explorer ($env:USERPROFILE + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")