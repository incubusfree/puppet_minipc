# manifest.pp

node 'ahmed-ramadan' {
# Define PowerShell path for ease of use
$powershell_path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

# Pin "This PC" to Taskbar
exec { 'Pin This PC':
  command => "${powershell_path} -Command \"\$shell = New-Object -ComObject Shell.Application; \$folder = \$shell.NameSpace(0); \$folder.Items() | Where-Object { \$_.Name -eq 'This PC' } | ForEach-Object { \$_.InvokeVerb('pin to taskbar') }\"",
  onlyif => "${powershell_path} -Command \"\$shell = New-Object -ComObject Shell.Application; \$folder = \$folder.NameSpace(0); \$folder.Items() | Where-Object { \$_.Name -eq 'This PC' -and \$_.IsLink }\"",
}


# Rename Computer to Station Name
exec { 'Rename Computer':
  command => "${powershell_path} -Command \"Rename-Computer -NewName 'Ahmed-Ramadan' -Force -Restart\"",
  unless  => "${powershell_path} -Command \"(Get-WmiObject -Class Win32_ComputerSystem).Name -eq 'Ahmed-Ramadan'\"",
}

# Remove All Icons from Desktop
exec { 'Remove Desktop Icons':
  command => "${powershell_path} -Command \"Get-ChildItem -Path 'C:\\Users\\CarGas\\Desktop' | Remove-Item -Force\"",
  require => Exec['Rename Computer'],
}

# Adjust Date and Time & Activate Windows Automatically
exec { 'Sync Date and Time & Activate Windows':
  command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"w32tm /resync; slmgr /ato\"",
  require => Exec['Remove Desktop Icons'],
}

# Enable Remote Desktop
exec { 'Enable Remote Desktop':
  command => "${powershell_path} -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0; Enable-NetFirewallRule -DisplayName 'Remote Desktop'\"",
  onlyif => "${powershell_path} -Command \"Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' | Select-Object -ExpandProperty fDenyTSConnections -eq 1\"",
}

# Disable Windows Firewall
exec { 'Disable Windows Firewall':
  command => "${powershell_path} -Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False\"",
  onlyif => "${powershell_path} -Command \"Get-NetFirewallProfile | Where-Object { \$_.Enabled -eq 'True' } | Measure-Object | Select-Object -ExpandProperty Count -gt 0\"",
}

#Background Services>Disabled
exec { 'Disable BITS':
  command => 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-Service -Name BITS -StartupType Disabled; Stop-Service -Name BITS -Force"',
  onlyif => 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-Service -Name BITS | Where-Object { $_.StartType -ne \'Disabled\' }"',
}

#Windows Update Dsable
service { 'wuauserv':
  ensure   => 'stopped',
  enable   => false,
  provider => 'windows',
}

#disable the requirement for Sign-in

exec { 'Set AutoAdminLogon':
  command => 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Set-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\' -Name \'AutoAdminLogon\' -Value 1"',
  onlyif => 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\' -Name \'AutoAdminLogon\' | Where-Object { $_.AutoAdminLogon -ne 1}"',
}

#Power management uncheck turn off this device to save Power
exec { 'Disable Wake on Magic Packet':
  command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Magic Packet' -DisplayValue 'Disabled'\"",
  onlyif  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"(Get-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Magic Packet').DisplayValue -eq 'Enabled'\"",
}

exec { 'Disable Wake on Pattern Match':
  command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Pattern Match' -DisplayValue 'Disabled'\"",
  onlyif  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"(Get-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Pattern Match').DisplayValue -eq 'Enabled'\"",
}


#never turn off the display
exec { 'turn_off_display':
    command => 'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 0 /f',
    path    => ['C:\\Windows\\System32'],
    unless  => 'reg query "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut | findstr "0"',
  }

# Disable Windows features

# Disable Device Lockdown
exec { 'Disable DeviceLockdown':
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Disable-WindowsOptionalFeature -Online -FeatureName DeviceLockdown -NoRestart\"",
    path    => ['C:\\Windows\\System32'],
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'DeviceLockdown' -and $_.State -eq 'Disabled' }\"",
}

# Disable Media Features
exec { 'Disable MediaFeatures':
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Disable-WindowsOptionalFeature -Online -FeatureName MediaFeatures -NoRestart\"",
    path    => ['C:\\Windows\\System32'],
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'MediaFeatures' -and $_.State -eq 'Disabled' }\"",
}

# Disable Microsoft Print to PDF
exec { 'Disable MicrosoftPrintToPDF':
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftPrintToPDF -NoRestart\"",
    path    => ['C:\\Windows\\System32'],
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'MicrosoftPrintToPDF' -and $_.State -eq 'Disabled' }\"",
}

# Disable Microsoft XPS Document Writer
exec { 'Disable MicrosoftXPSDocumentWriter':
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftXPSDocumentWriter -NoRestart\"",
    path    => ['C:\\Windows\\System32'],
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'MicrosoftXPSDocumentWriter' -and $_.State -eq 'Disabled' }\"",
}

# Disable Print and Document Services
exec { 'Disable PrintAndDocumentServices':
    command => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Disable-WindowsOptionalFeature -Online -FeatureName PrintAndDocumentServices -NoRestart\"",
    path    => ['C:\\Windows\\System32'],
    unless  => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command \"Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'PrintAndDocumentServices' -and $_.State -eq 'Disabled' }\"",
}	

}
