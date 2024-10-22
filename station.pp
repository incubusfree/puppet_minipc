node 'default' {
  # Define CMD and PowerShell path for ease of use
  $powershell_path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$cmd = 'C:\Windows\System32\cmd.exe'


  #T1 Pin "This PC" to Taskbar
  exec { 'Pin This PC':
    command => "${powershell_path} -Command \"\$shell = New-Object -ComObject Shell.Application; \$folder = \$shell.NameSpace(0); \$folder.Items() | Where-Object { \$_.Name -eq 'This PC' } | ForEach-Object { \$_.InvokeVerb('pin to taskbar') }\"",
   #onlyif  => "${powershell_path} -Command \"\$shell = New-Object -ComObject Shell.Application; \$folder = \$folder.NameSpace(0); \$folder.Items() | Where-Object { \$_.Name -eq 'This PC' -and \$_.IsLink }\"",
    logoutput => true,
  }

  #T2 Rename Computer to Station Name
  #exec { 'Rename Computer':
   # command => "${powershell_path} -Command \"Rename-Computer -NewName 'Ahmed-Ramadan' -Force -Restart\"",
   # unless  => "${powershell_path} -Command \"(Get-WmiObject -Class Win32_ComputerSystem).Name -eq 'Ahmed-Ramadan'\"",
    #logoutput => true,
  #}

  #T3 Remove All Icons from Desktop
  exec { 'Remove Desktop Icons':
    command => "${powershell_path} -Command \"Get-ChildItem -Path 'C:\\Users\\CarGas\\Desktop' | Remove-Item -Force\"",
    #require => Exec['Rename Computer'],
    logoutput => true,
  }

  #T4 Sync Date and Time & Activate Windows Automatically
  exec { 'Sync Date and Time & Activate Windows':
    command => "${powershell_path} -Command \"w32tm /resync; slmgr /ato\"",
    #require => Exec['Remove Desktop Icons'],
    logoutput => true,
  }

  #T5 Enable Remote Desktop
  exec { 'Enable Remote Desktop':
    command => "${powershell_path} -Command \"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0; Enable-NetFirewallRule -DisplayName 'Remote Desktop'\"",
    onlyif  => "${powershell_path} -Command \"Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' | Select-Object -ExpandProperty fDenyTSConnections -eq 1\"",
    logoutput => true,
  }

  #T6 Disable Windows Firewall
  exec { 'Disable Windows Firewall':
    command => "${powershell_path} -Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False\"",
    onlyif  => "${powershell_path} -Command \"Get-NetFirewallProfile | Where-Object { \$_.Enabled -eq 'True' } | Measure-Object | Select-Object -ExpandProperty Count -gt 0\"",
    logoutput => true,
  }

  #T7 Disable Background Intelligent Transfer Service (BITS)
  exec { 'Disable BITS':
    command => "${powershell_path} -Command \"Set-Service -Name BITS -StartupType Disabled; Stop-Service -Name BITS -Force\"",
    onlyif  => "${powershell_path} -Command \"Get-Service -Name BITS | Where-Object { \$_.StartType -ne 'Disabled' }\"",
    logoutput => true,
  }

  #T8 Stop and disable Windows Update service
  service { 'wuauserv':
    ensure   => 'stopped',
    enable   => false,
    provider => 'windows',
  }

  #T9 Enable AutoAdminLogon
  exec { 'Set AutoAdminLogon':
    command => "${powershell_path} -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI' -Name 'AutoAdminLogon' -Value 1\"",
    onlyif  => "${powershell_path} -Command \"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI' -Name 'AutoAdminLogon' | Where-Object { \$_.AutoAdminLogon -ne 1}\"",
    logoutput => true,
  }

  #T10 Disable Wake on Magic Packet
 # exec { 'Disable Wake on Magic Packet':
  #  command => "${powershell_path} -Command \"Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Magic Packet' -DisplayValue 'Disabled'\"",
   # onlyif  => "${powershell_path} -Command \"(Get-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Magic Packet').DisplayValue -eq 'Enabled'\"",
    #logoutput => true,
  #}

  #T11 Disable Wake on Pattern Match
  #exec { 'Disable Wake on Pattern Match':
   # command => "${powershell_path} -Command \"Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Pattern Match' -DisplayValue 'Disabled'\"",
   # onlyif  => "${powershell_path} -Command \"(Get-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Wake on Pattern Match').DisplayValue -eq 'Enabled'\"",
    #logoutput => true,
#  }

  #T12 Never turn off the display
  exec { 'turn_off_display':
    command => 'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d 0 /f',
    path    => ['C:\\Windows\\System32'],
    unless  => 'reg query "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut | findstr "0"',
    logoutput => true,
  }

  #T13 Disable optional Windows features
  exec { 'Disable DeviceLockdown':
    command => "${powershell_path} -Command \"Disable-WindowsOptionalFeature -Online -FeatureName DeviceLockdown -NoRestart\"",
    unless  => "${powershell_path} -Command \"Get-WindowsOptionalFeature -Online | Where-Object { \$_.FeatureName -eq 'DeviceLockdown' -and \$_.State -eq 'Disabled' }\"",
    logoutput => true,
  }
  #T14 Diable Media Features
  exec { 'Disable WindowsMediaPlayer':
    command => "${powershell_path} -Command \"Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart\"",
    #unless  => "${powershell_path} -Command \"Get-WindowsOptionalFeature -Online | Where-Object { \$_.FeatureName -eq 'WindowsMediaPlayer' -and \$_.State -eq 'Disabled' }\"",
    logoutput => true,
  }
 #T15 Disable MicrosoftPrintPDF
  exec { 'Disable  Printing-PrintToPDFServices-Features':
    command => "${powershell_path} -Command \"Disable-WindowsOptionalFeature -Online -FeatureName Printing-PrintToPDFServices-Features -NoRestart\"",
    #unless  => "${powershell_path} -Command \"Get-WindowsOptionalFeature -Online | Where-Object { \$_.FeatureName -eq ' Printing-PrintToPDFServices-Features' -and \$_.State -eq 'Disabled' }\"",
    logoutput => true,
  }
 #T16 Disable MicrosoftXPSDocumentWriter
  exec { 'Printing-XPSServices-Features':
    command => "${powershell_path} -Command \"Disable-WindowsOptionalFeature -Online -FeatureName Printing-XPSServices-Features -NoRestart\"",
    #unless  => "${powershell_path} -Command \"Get-WindowsOptionalFeature -Online | Where-Object { \$_.FeatureName -eq 'Printing-XPSServices-Features' -and \$_.State -eq 'Disabled' }\"",
    logoutput => true,
  }
 #T17 DisableAndDocumentServices
  exec { 'Disable Printing-Foundation-Features':
    command => "${powershell_path} -Command \"Disable-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features -NoRestart\"",
    #unless  => "${powershell_path} -Command \"Get-WindowsOptionalFeature -Online | Where-Object { \$_.FeatureName -eq 'Printing-Foundation-Features' -and \$_.State -eq 'Disabled' }\"",
    logoutput => true,
  }
#T18 Ensure the USB drive (D:) is available
exec { 'Check USB Drive':
  command   => '${cmd} /c "if exist D:\ (echo USB drive found) else (echo USB drive not found)"',
  logoutput => true,
}

exec { 'Install Python from USB':
  command   => 'D:\\MiniPC\\python-3.12.6-amd64.exe /silent',  # Adjust the installation command as needed
  logoutput => true,
  require   => Exec['Check USB Drive'],
}

exec { 'Install SQL from USB':
  command   => 'D:\\MiniPC\\SQL\\SSMS-Setup-ENU.exe /silent',  # Adjust the installation command as needed
  logoutput => true,
  require   => Exec['Check USB Drive'],
}


}

#node 'ahmed-ramadan'{
  # Define PowerShell path for ease of use
 # $powershell_path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
#exec { 'Rename Computer':
 #   command => "${powershell_path} -Command \"Rename-Computer -NewName 'Ahmed-Ramadan' -Force -Restart\"",
  #  unless  => "${powershell_path} -Command \"(Get-WmiObject -Class Win32_ComputerSystem).Name -eq 'Ahmed-Ramadan'\"",
   # logoutput => true,
  #}
 #}

#node 'cargas'{
  # Define PowerShell path for ease of use
 # $powershell_path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
#exec { 'Rename Computer':
 #   command => "${powershell_path} -Command \"Rename-Computer -NewName 'mohamed-yousri' -Force -Restart\"",
  #  unless  => "${powershell_path} -Command \"(Get-WmiObject -Class Win32_ComputerSystem).Name -eq 'mohamed-yousri'\"",
   # logoutput => true,
  #}
 #}

