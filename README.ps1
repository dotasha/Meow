
# 200 FEATURES OF CHAOS AND DESTRUCTION

function Show-RainbowAsciiIntro {
      Clear-Host
      $asciiArt = @"
  ▄▄▄      ▓█████▄  ███▄    █  ▄▄▄       ███▄    █ 
  ▒████▄    ▒██▀ ██▌ ██ ▀█   █ ▒████▄     ██ ▀█   █ 
  ▒██  ▀█▄  ░██   █▌▓██  ▀█ ██▒▒██  ▀█▄  ▓██  ▀█ ██▒
  ░██▄▄▄▄██ ░▓█▄   ▌▓██▒  ▐▌██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
   ▓█   ▓██▒░▒████▓ ▒██░   ▓██░ ▓█   ▓██▒▒██░   ▓██░
   ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
    ▒   ▒▒ ░ ░ ▒  ▒ ░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ▒░
    ░   ▒    ░ ░  ░    ░   ░ ░   ░   ▒      ░   ░ ░ 
        ░  ░   ░             ░       ░  ░         ░ 
             ░                                      
  "@
  
      # Define rainbow colors
      $rainbowColors = @("Red", "Yellow", "Green", "Cyan", "Blue", "Magenta")
  
      # Split the ASCII art into lines
      $lines = $asciiArt -split "`n"
  
      # Display each line in a different color
      for ($i = 0; $i -lt $lines.Length; $i++) {
          $color = $rainbowColors[$i % $rainbowColors.Length]
          Write-Host $lines[$i] -ForegroundColor $color
      }
  }
  
  # Main script
  Show-RainbowAsciiIntro
  Start-Sleep -Seconds 10
  
  # Main script
  Show-RainbowAsciiIntro
  Start-Sleep -Seconds 10

# Feature 1: Force shutdown the laptop
function Invoke-ForceShutdown {
    Stop-Computer -Force
}

# Feature 2: Schedule a shutdown in 60 seconds
function Invoke-ScheduledShutdown {
    shutdown /s /t 60
}

# Feature 3: Abort a scheduled shutdown
function Invoke-AbortShutdown {
    shutdown /a
}

# Feature 4: Restart the laptop
function Invoke-ForceRestart {
    Restart-Computer -Force
}

# Feature 5: Log off the current user
function Invoke-ForceLogoff {
    shutdown /l
}

# Feature 6: Hibernate the laptop
function Invoke-Hibernate {
    shutdown /h
}

# Feature 7: Put the laptop to sleep
function Invoke-Sleep {
    Add-Type -TypeDefinition @"
    using System.Runtime.InteropServices;
    public class Power {
        [DllImport("powrprof.dll", SetLastError = true)]
        public static extern bool SetSuspendState(bool hibernate, bool forceCritical, bool disableWakeEvent);
    }
"@
    [Power]::SetSuspendState($false, $false, $false)
}

# Feature 8: Disable the power button
function Disable-PowerButton {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0
}

# Feature 9: Enable the power button
function Enable-PowerButton {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 1
}

# Feature 10: Disable the sleep button
function Disable-SleepButton {
    powercfg /h off
}

# Feature 11: Enable the sleep button
function Enable-SleepButton {
    powercfg /h on
}

# Feature 12: Disable hibernation
function Disable-Hibernation {
    powercfg /h off
}

# Feature 13: Enable hibernation
function Enable-Hibernation {
    powercfg /h on
}

# Feature 14: Disable fast startup
function Disable-FastStartup {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0
}

# Feature 15: Enable fast startup
function Enable-FastStartup {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 1
}

# Feature 16: Disable USB ports
function Disable-USBPorts {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
}

# Feature 17: Enable USB ports
function Enable-USBPorts {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3
}

# Feature 18: Disable Wi-Fi
function Disable-WiFi {
    netsh interface set interface "Wi-Fi" admin=disable
}

# Feature 19: Enable Wi-Fi
function Enable-WiFi {
    netsh interface set interface "Wi-Fi" admin=enable
}

# Feature 20: Disable Bluetooth
function Disable-Bluetooth {
    Get-PnpDevice | Where-Object {$_.FriendlyName -like "*Bluetooth*"} | Disable-PnpDevice -Confirm:$false
}

# Feature 21: Enable Bluetooth
function Enable-Bluetooth {
    Get-PnpDevice | Where-Object {$_.FriendlyName -like "*Bluetooth*"} | Enable-PnpDevice -Confirm:$false
}

# Feature 22: Disable Network Adapters
function Disable-NetworkAdapters {
    Get-NetAdapter | Disable-NetAdapter -Confirm:$false
}

# Feature 23: Enable Network Adapters
function Enable-NetworkAdapters {
    Get-NetAdapter | Enable-NetAdapter -Confirm:$false
}

# Feature 24: Disable Firewall
function Disable-Firewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
}

# Feature 25: Enable Firewall
function Enable-Firewall {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# Feature 26: Disable Windows Defender
function Disable-WindowsDefender {
    Set-MpPreference -DisableRealtimeMonitoring $true
}

# Feature 27: Enable Windows Defender
function Enable-WindowsDefender {
    Set-MpPreference -DisableRealtimeMonitoring $false
}

# Feature 28: Disable Windows Update
function Disable-WindowsUpdate {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1
}

# Feature 29: Enable Windows Update
function Enable-WindowsUpdate {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
}

# Feature 30: Disable Task Manager
function Disable-TaskManager {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 1
}

# Feature 31: Enable Task Manager
function Enable-TaskManager {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 0
}

# Feature 32: Disable Registry Editor
function Disable-RegistryEditor {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -Value 1
}

# Feature 33: Enable Registry Editor
function Enable-RegistryEditor {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -Value 0
}

# Feature 34: Disable Command Prompt
function Disable-CommandPrompt {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Value 1
}

# Feature 35: Enable Command Prompt
function Enable-CommandPrompt {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Value 0
}

# Feature 36: Disable PowerShell
function Disable-PowerShell {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Restricted"
}

# Feature 37: Enable PowerShell
function Enable-PowerShell {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Unrestricted"
}

# Feature 38: Disable Remote Desktop
function Disable-RemoteDesktop {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
}

# Feature 39: Enable Remote Desktop
function Enable-RemoteDesktop {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
}

# Feature 40: Disable AutoPlay
function Disable-AutoPlay {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
}

# Feature 41: Enable AutoPlay
function Enable-AutoPlay {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0
}

# Feature 42: Disable Cortana
function Disable-Cortana {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0
}

# Feature 43: Enable Cortana
function Enable-Cortana {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 1
}

# Feature 44: Disable Telemetry
function Disable-Telemetry {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
}

# Feature 45: Enable Telemetry
function Enable-Telemetry {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1
}

# Feature 46: Disable Error Reporting
function Disable-ErrorReporting {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1
}

# Feature 47: Enable Error Reporting
function Enable-ErrorReporting {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 0
}

# Feature 48: Disable Windows Search
function Disable-WindowsSearch {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 49: Enable Windows Search
function Enable-WindowsSearch {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 50: Disable Print Spooler
function Disable-PrintSpooler {
    Stop-Service -Name "Spooler" -Force
    Set-Service -Name "Spooler" -StartupType Disabled
}

# Feature 51: Enable Print Spooler
function Enable-PrintSpooler {
    Set-Service -Name "Spooler" -StartupType Automatic
    Start-Service -Name "Spooler"
}

# Feature 52: Disable Remote Registry
function Disable-RemoteRegistry {
    Stop-Service -Name "RemoteRegistry" -Force
    Set-Service -Name "RemoteRegistry" -StartupType Disabled
}

# Feature 53: Enable Remote Registry
function Enable-RemoteRegistry {
    Set-Service -Name "RemoteRegistry" -StartupType Automatic
    Start-Service -Name "RemoteRegistry"
}

# Feature 54: Disable Windows Defender Firewall Service
function Disable-WindowsDefenderFirewallService {
    Stop-Service -Name "MpsSvc" -Force
    Set-Service -Name "MpsSvc" -StartupType Disabled
}

# Feature 55: Enable Windows Defender Firewall Service
function Enable-WindowsDefenderFirewallService {
    Set-Service -Name "MpsSvc" -StartupType Automatic
    Start-Service -Name "MpsSvc"
}

# Feature 56: Disable Windows Update Service
function Disable-WindowsUpdateService {
    Stop-Service -Name "wuauserv" -Force
    Set-Service -Name "wuauserv" -StartupType Disabled
}

# Feature 57: Enable Windows Update Service
function Enable-WindowsUpdateService {
    Set-Service -Name "wuauserv" -StartupType Automatic
    Start-Service -Name "wuauserv"
}

# Feature 58: Disable Background Intelligent Transfer Service
function Disable-BITS {
    Stop-Service -Name "BITS" -Force
    Set-Service -Name "BITS" -StartupType Disabled
}

# Feature 59: Enable Background Intelligent Transfer Service
function Enable-BITS {
    Set-Service -Name "BITS" -StartupType Automatic
    Start-Service -Name "BITS"
}

# Feature 60: Disable Superfetch
function Disable-Superfetch {
    Stop-Service -Name "SysMain" -Force
    Set-Service -Name "SysMain" -StartupType Disabled
}

# Feature 61: Enable Superfetch
function Enable-Superfetch {
    Set-Service -Name "SysMain" -StartupType Automatic
    Start-Service -Name "SysMain"
}

# Feature 62: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 63: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 64: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 65: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 66: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 67: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 68: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 69: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 70: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 71: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 72: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 73: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 74: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 75: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 76: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 77: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 78: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 79: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 80: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 81: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 82: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 83: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 84: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 85: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 86: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 87: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 88: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 89: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 90: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 91: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 92: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 93: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 94: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 95: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 96: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 97: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 98: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 99: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 100: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 101: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 102: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 103: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 104: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 105: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 106: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 107: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 108: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 109: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 110: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 111: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 112: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 113: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 114: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 115: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 116: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 117: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 118: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 119: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 120: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 121: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 122: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 123: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 124: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 125: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 126: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 127: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 128: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 129: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 130: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 131: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 132: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 133: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 134: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 135: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 136: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 137: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 138: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 139: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 140: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 141: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 142: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 143: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 144: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 145: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 146: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 147: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 148: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 149: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 150: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 151: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 152: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 153: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 154: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 155: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 156: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 157: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 158: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 159: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 160: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 161: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 162: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 163: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 164: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 165: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 166: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 167: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 168: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 169: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 170: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 171: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 172: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 173: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 174: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 175: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 176: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 177: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 178: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 179: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 180: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 181: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 182: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 183: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 184: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 185: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 186: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 187: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 188: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 189: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 190: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 191: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 192: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 193: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 194: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 195: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 196: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 197: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 198: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 199: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 200: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 201: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 202: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 203: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 204: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 205: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 206: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 207: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 208: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 209: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 210: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 211: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 212: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 213: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 214: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 215: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 216: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 217: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 218: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 219: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 220: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 221: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 222: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 223: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 224: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 225: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 226: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 227: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 228: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 229: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 230: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 231: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 232: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 233: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 234: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 235: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 236: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 237: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 238: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 239: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 240: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 241: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 242: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 243: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 244: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 245: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 246: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 247: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 248: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 249: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 250: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 251: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 252: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 253: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 254: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 255: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 256: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 257: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 258: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 259: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 260: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 261: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 262: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 263: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 264: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 265: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 266: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 267: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 268: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 269: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 270: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 271: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 272: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 273: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 274: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 275: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 276: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 277: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 278: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 279: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 280: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 281: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 282: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 283: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 284: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 285: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 286: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 287: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 288: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 289: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 290: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 291: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 292: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 293: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 294: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 295: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 296: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 297: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 298: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 299: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 300: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 301: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 302: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 303: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 304: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 305: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 306: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 307: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 308: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 309: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 310: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 311: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 312: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 313: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 314: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 315: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 316: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 317: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 318: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 319: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 320: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 321: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 322: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 323: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 324: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 325: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 326: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 327: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 328: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 329: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 330: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 331: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 332: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 333: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 334: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 335: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 336: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 337: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 338: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 339: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 340: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 341: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 342: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 343: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 344: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 345: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 346: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 347: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 348: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 349: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 350: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 351: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 352: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 353: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 354: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 355: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 356: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 357: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 358: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 359: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 360: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 361: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 362: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 363: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 364: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 365: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 366: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 367: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 368: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 369: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 370: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 371: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 372: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 373: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 374: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 375: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 376: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 377: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}

# Feature 378: Disable Windows Management Instrumentation Service
function Disable-WindowsManagementInstrumentationService {
    Stop-Service -Name "Winmgmt" -Force
    Set-Service -Name "Winmgmt" -StartupType Disabled
}

# Feature 379: Enable Windows Management Instrumentation Service
function Enable-WindowsManagementInstrumentationService {
    Set-Service -Name "Winmgmt" -StartupType Automatic
    Start-Service -Name "Winmgmt"
}

# Feature 380: Disable Windows Remote Management Service
function Disable-WindowsRemoteManagementService {
    Stop-Service -Name "WinRM" -Force
    Set-Service -Name "WinRM" -StartupType Disabled
}

# Feature 381: Enable Windows Remote Management Service
function Enable-WindowsRemoteManagementService {
    Set-Service -Name "WinRM" -StartupType Automatic
    Start-Service -Name "WinRM"
}

# Feature 382: Disable Windows Time Service
function Disable-WindowsTimeService {
    Stop-Service -Name "W32Time" -Force
    Set-Service -Name "W32Time" -StartupType Disabled
}

# Feature 383: Enable Windows Time Service
function Enable-WindowsTimeService {
    Set-Service -Name "W32Time" -StartupType Automatic
    Start-Service -Name "W32Time"
}

# Feature 384: Disable Windows Update Medic Service
function Disable-WindowsUpdateMedicService {
    Stop-Service -Name "WaaSMedicSvc" -Force
    Set-Service -Name "WaaSMedicSvc" -StartupType Disabled
}

# Feature 385: Enable Windows Update Medic Service
function Enable-WindowsUpdateMedicService {
    Set-Service -Name "WaaSMedicSvc" -StartupType Automatic
    Start-Service -Name "WaaSMedicSvc"
}

# Feature 386: Disable Windows Modules Installer Worker
function Disable-WindowsModulesInstallerWorker {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 387: Enable Windows Modules Installer Worker
function Enable-WindowsModulesInstallerWorker {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 388: Disable Windows Error Reporting Service
function Disable-WindowsErrorReportingService {
    Stop-Service -Name "WerSvc" -Force
    Set-Service -Name "WerSvc" -StartupType Disabled
}

# Feature 389: Enable Windows Error Reporting Service
function Enable-WindowsErrorReportingService {
    Set-Service -Name "WerSvc" -StartupType Automatic
    Start-Service -Name "WerSvc"
}

# Feature 390: Disable Windows Audio Service
function Disable-WindowsAudioService {
    Stop-Service -Name "Audiosrv" -Force
    Set-Service -Name "Audiosrv" -StartupType Disabled
}

# Feature 391: Enable Windows Audio Service
function Enable-WindowsAudioService {
    Set-Service -Name "Audiosrv" -StartupType Automatic
    Start-Service -Name "Audiosrv"
}

# Feature 392: Disable Windows Audio Endpoint Builder Service
function Disable-WindowsAudioEndpointBuilderService {
    Stop-Service -Name "AudioEndpointBuilder" -Force
    Set-Service -Name "AudioEndpointBuilder" -StartupType Disabled
}

# Feature 393: Enable Windows Audio Endpoint Builder Service
function Enable-WindowsAudioEndpointBuilderService {
    Set-Service -Name "AudioEndpointBuilder" -StartupType Automatic
    Start-Service -Name "AudioEndpointBuilder"
}

# Feature 394: Disable Windows Font Cache Service
function Disable-WindowsFontCacheService {
    Stop-Service -Name "FontCache" -Force
    Set-Service -Name "FontCache" -StartupType Disabled
}

# Feature 395: Enable Windows Font Cache Service
function Enable-WindowsFontCacheService {
    Set-Service -Name "FontCache" -StartupType Automatic
    Start-Service -Name "FontCache"
}

# Feature 396: Disable Windows Image Acquisition Service
function Disable-WindowsImageAcquisitionService {
    Stop-Service -Name "stisvc" -Force
    Set-Service -Name "stisvc" -StartupType Disabled
}

# Feature 397: Enable Windows Image Acquisition Service
function Enable-WindowsImageAcquisitionService {
    Set-Service -Name "stisvc" -StartupType Automatic
    Start-Service -Name "stisvc"
}

# Feature 398: Disable Windows Installer Service
function Disable-WindowsInstallerService {
    Stop-Service -Name "msiserver" -Force
    Set-Service -Name "msiserver" -StartupType Disabled
}

# Feature 399: Enable Windows Installer Service
function Enable-WindowsInstallerService {
    Set-Service -Name "msiserver" -StartupType Manual
    Start-Service -Name "msiserver"
}

# Feature 400: Disable Windows Modules Installer Service
function Disable-WindowsModulesInstallerService {
    Stop-Service -Name "TrustedInstaller" -Force
    Set-Service -Name "TrustedInstaller" -StartupType Disabled
}

# Feature 401: Enable Windows Modules Installer Service
function Enable-WindowsModulesInstallerService {
    Set-Service -Name "TrustedInstaller" -StartupType Manual
    Start-Service -Name "TrustedInstaller"
}

# Feature 402: Disable Windows Search Indexer Service
function Disable-WindowsSearchIndexerService {
    Stop-Service -Name "WSearch" -Force
    Set-Service -Name "WSearch" -StartupType Disabled
}

# Feature 403: Enable Windows Search Indexer Service
function Enable-WindowsSearchIndexerService {
    Set-Service -Name "WSearch" -StartupType Automatic
    Start-Service -Name "WSearch"
}

# Feature 404: Disable Windows Defender Antivirus Network Inspection Service
function Disable-WindowsDefenderAntivirusNetworkInspectionService {
    Stop-Service -Name "WdNisSvc" -Force
    Set-Service -Name "WdNisSvc" -StartupType Disabled
}

# Feature 405: Enable Windows Defender Antivirus Network Inspection Service
function Enable-WindowsDefenderAntivirusNetworkInspectionService {
    Set-Service -Name "WdNisSvc" -StartupType Automatic
    Start-Service -Name "WdNisSvc"
}

# Feature 406: Disable Windows Defender Antivirus Service
function Disable-WindowsDefenderAntivirusService {
    Stop-Service -Name "WinDefend" -Force
    Set-Service -Name "WinDefend" -StartupType Disabled
}

# Feature 407: Enable Windows Defender Antivirus Service
function Enable-WindowsDefenderAntivirusService {
    Set-Service -Name "WinDefend" -StartupType Automatic
    Start-Service -Name "WinDefend"
}

# Feature 408: Disable Windows Defender Security Center Service
function Disable-WindowsDefenderSecurityCenterService {
    Stop-Service -Name "SecurityHealthService" -Force
    Set-Service -Name "SecurityHealthService" -StartupType Disabled
}

# Feature 409: Enable Windows Defender Security Center Service
function Enable-WindowsDefenderSecurityCenterService {
    Set-Service -Name "SecurityHealthService" -StartupType Automatic
    Start-Service -Name "SecurityHealthService"
}

# Feature 410: Disable Windows Event Log Service
function Disable-WindowsEventLogService {
    Stop-Service -Name "EventLog" -Force
    Set-Service -Name "EventLog" -StartupType Disabled
}

# Feature 411: Enable Windows Event Log Service
function Enable-WindowsEventLogService {
    Set-Service -Name "EventLog" -StartupType Automatic
    Start-Service -Name "EventLog"
}

# Feature 412: Disable Windows Firewall Authorization Driver
function Disable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 4
}

# Feature 413: Enable Windows Firewall Authorization Driver
function Enable-WindowsFirewallAuthorizationDriver {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mpsdrv" -Name "Start" -Value 2
}
 

# Feature 415: IP Delay (Displays your current IP every minute)
function Get-PublicIP {
      try {
          $ip = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content
          return $ip
      } catch {
          Write-Host "Failed to fetch public IP." -ForegroundColor Red
          return $null
      }
  }
  
  function Start-IPDelay {
      while ($true) {
          $currentIP = Get-PublicIP
          if ($currentIP) {
              Write-Host "Current Public IP: $currentIP" -ForegroundColor Cyan
          }
          Write-Host "Waiting for 1 minute..." -ForegroundColor Yellow
          Start-Sleep -Seconds 60
      }
  }
  

# Function to display the menu
function Show-Menu {
      Clear-Host
      Write-Host "============================================="
      Write-Host "ZORG-MASTER👽'S MALEVOLENT POWERSHELL SCRIPT"
      Write-Host "============================================="
      Write-Host "1. Force shutdown the laptop"
      Write-Host "2. Schedule a shutdown in 60 seconds"
      Write-Host "3. Abort a scheduled shutdown"
      Write-Host "4. Restart the laptop"
      Write-Host "5. Log off the current user"
      Write-Host "6. Hibernate the laptop"
      Write-Host "7. Put the laptop to sleep"
      Write-Host "8. Disable the power button"
      Write-Host "9. Enable the power button"
      Write-Host "10. Disable the sleep button"
      Write-Host "11. Enable the sleep button"
      Write-Host "12. Disable hibernation"
      Write-Host "13. Enable hibernation"
      Write-Host "14. Disable fast startup"
      Write-Host "15. Enable fast startup"
      Write-Host "16. Disable USB ports"
      Write-Host "17. Enable USB ports"
      Write-Host "18. Disable Wi-Fi"
      Write-Host "19. Enable Wi-Fi"
      Write-Host "20. Disable Bluetooth"
      Write-Host "21. Enable Bluetooth"
      Write-Host "22. Disable Network Adapters"
      Write-Host "23. Enable Network Adapters"
      Write-Host "24. Disable Firewall"
      Write-Host "25. Enable Firewall"
      Write-Host "26. Disable Windows Defender"
      Write-Host "27. Enable Windows Defender"
      Write-Host "28. Disable Windows Update"
      Write-Host "29. Enable Windows Update"
      Write-Host "30. Disable Task Manager"
      Write-Host "31. Enable Task Manager"
      Write-Host "32. Disable Registry Editor"
      Write-Host "33. Enable Registry Editor"
      Write-Host "34. Disable Command Prompt"
      Write-Host "35. Enable Command Prompt"
      Write-Host "36. Disable PowerShell"
      Write-Host "37. Enable PowerShell"
      Write-Host "38. Disable Remote Desktop"
      Write-Host "39. Enable Remote Desktop"
      Write-Host "40. Disable AutoPlay"
      Write-Host "41. Enable AutoPlay"
      Write-Host "42. Disable Cortana"
      Write-Host "43. Enable Cortana"
      Write-Host "44. Disable Telemetry"
      Write-Host "45. Enable Telemetry"
      Write-Host "46. Disable Error Reporting"
      Write-Host "47. Enable Error Reporting"
      Write-Host "48. Disable Windows Search"
      Write-Host "49. Enable Windows Search"
      Write-Host "50. Disable Print Spooler"
      Write-Host "51. Enable Print Spooler"
      Write-Host "52. Disable Remote Registry"
      Write-Host "53. Enable Remote Registry"
      Write-Host "54. Disable Windows Defender Firewall Service"
      Write-Host "55. Enable Windows Defender Firewall Service"
      Write-Host "56. Disable Windows Update Service"
      Write-Host "57. Enable Windows Update Service"
      Write-Host "58. Disable Background Intelligent Transfer Service"
      Write-Host "59. Enable Background Intelligent Transfer Service"
      Write-Host "60. Disable Superfetch"
      Write-Host "61. Enable Superfetch"
      Write-Host "62. Disable Windows Time Service"
      Write-Host "63. Enable Windows Time Service"
      Write-Host "64. Disable Windows Error Reporting Service"
      Write-Host "65. Enable Windows Error Reporting Service"
      Write-Host "66. Disable Windows Audio Service"
      Write-Host "67. Enable Windows Audio Service"
      Write-Host "68. Disable Windows Audio Endpoint Builder Service"
      Write-Host "69. Enable Windows Audio Endpoint Builder Service"
      Write-Host "70. Disable Windows Font Cache Service"
      Write-Host "71. Enable Windows Font Cache Service"
      Write-Host "72. Disable Windows Image Acquisition Service"
      Write-Host "73. Enable Windows Image Acquisition Service"
      Write-Host "74. Disable Windows Installer Service"
      Write-Host "75. Enable Windows Installer Service"
      Write-Host "76. Disable Windows Modules Installer Service"
      Write-Host "77. Enable Windows Modules Installer Service"
      Write-Host "78. Disable Windows Search Indexer Service"
      Write-Host "79. Enable Windows Search Indexer Service"
      Write-Host "80. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "81. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "82. Disable Windows Defender Antivirus Service"
      Write-Host "83. Enable Windows Defender Antivirus Service"
      Write-Host "84. Disable Windows Defender Security Center Service"
      Write-Host "85. Enable Windows Defender Security Center Service"
      Write-Host "86. Disable Windows Event Log Service"
      Write-Host "87. Enable Windows Event Log Service"
      Write-Host "88. Disable Windows Firewall Authorization Driver"
      Write-Host "89. Enable Windows Firewall Authorization Driver"
      Write-Host "90. Disable Windows Management Instrumentation Service"
      Write-Host "91. Enable Windows Management Instrumentation Service"
      Write-Host "92. Disable Windows Remote Management Service"
      Write-Host "93. Enable Windows Remote Management Service"
      Write-Host "94. Disable Windows Time Service"
      Write-Host "95. Enable Windows Time Service"
      Write-Host "96. Disable Windows Update Medic Service"
      Write-Host "97. Enable Windows Update Medic Service"
      Write-Host "98. Disable Windows Modules Installer Worker"
      Write-Host "99. Enable Windows Modules Installer Worker"
      Write-Host "100. Disable Windows Error Reporting Service"
      Write-Host "101. Enable Windows Error Reporting Service"
      Write-Host "102. Disable Windows Audio Service"
      Write-Host "103. Enable Windows Audio Service"
      Write-Host "104. Disable Windows Audio Endpoint Builder Service"
      Write-Host "105. Enable Windows Audio Endpoint Builder Service"
      Write-Host "106. Disable Windows Font Cache Service"
      Write-Host "107. Enable Windows Font Cache Service"
      Write-Host "108. Disable Windows Image Acquisition Service"
      Write-Host "109. Enable Windows Image Acquisition Service"
      Write-Host "110. Disable Windows Installer Service"
      Write-Host "111. Enable Windows Installer Service"
      Write-Host "112. Disable Windows Modules Installer Service"
      Write-Host "113. Enable Windows Modules Installer Service"
      Write-Host "114. Disable Windows Search Indexer Service"
      Write-Host "115. Enable Windows Search Indexer Service"
      Write-Host "116. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "117. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "118. Disable Windows Defender Antivirus Service"
      Write-Host "119. Enable Windows Defender Antivirus Service"
      Write-Host "120. Disable Windows Defender Security Center Service"
      Write-Host "121. Enable Windows Defender Security Center Service"
      Write-Host "122. Disable Windows Event Log Service"
      Write-Host "123. Enable Windows Event Log Service"
      Write-Host "124. Disable Windows Firewall Authorization Driver"
      Write-Host "125. Enable Windows Firewall Authorization Driver"
      Write-Host "126. Disable Windows Management Instrumentation Service"
      Write-Host "127. Enable Windows Management Instrumentation Service"
      Write-Host "128. Disable Windows Remote Management Service"
      Write-Host "129. Enable Windows Remote Management Service"
      Write-Host "130. Disable Windows Time Service"
      Write-Host "131. Enable Windows Time Service"
      Write-Host "132. Disable Windows Update Medic Service"
      Write-Host "133. Enable Windows Update Medic Service"
      Write-Host "134. Disable Windows Modules Installer Worker"
      Write-Host "135. Enable Windows Modules Installer Worker"
      Write-Host "136. Disable Windows Error Reporting Service"
      Write-Host "137. Enable Windows Error Reporting Service"
      Write-Host "138. Disable Windows Audio Service"
      Write-Host "139. Enable Windows Audio Service"
      Write-Host "140. Disable Windows Audio Endpoint Builder Service"
      Write-Host "141. Enable Windows Audio Endpoint Builder Service"
      Write-Host "142. Disable Windows Font Cache Service"
      Write-Host "143. Enable Windows Font Cache Service"
      Write-Host "144. Disable Windows Image Acquisition Service"
      Write-Host "145. Enable Windows Image Acquisition Service"
      Write-Host "146. Disable Windows Installer Service"
      Write-Host "147. Enable Windows Installer Service"
      Write-Host "148. Disable Windows Modules Installer Service"
      Write-Host "149. Enable Windows Modules Installer Service"
      Write-Host "150. Disable Windows Search Indexer Service"
      Write-Host "151. Enable Windows Search Indexer Service"
      Write-Host "152. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "153. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "154. Disable Windows Defender Antivirus Service"
      Write-Host "155. Enable Windows Defender Antivirus Service"
      Write-Host "156. Disable Windows Defender Security Center Service"
      Write-Host "157. Enable Windows Defender Security Center Service"
      Write-Host "158. Disable Windows Event Log Service"
      Write-Host "159. Enable Windows Event Log Service"
      Write-Host "160. Disable Windows Firewall Authorization Driver"
      Write-Host "161. Enable Windows Firewall Authorization Driver"
      Write-Host "162. Disable Windows Management Instrumentation Service"
      Write-Host "163. Enable Windows Management Instrumentation Service"
      Write-Host "164. Disable Windows Remote Management Service"
      Write-Host "165. Enable Windows Remote Management Service"
      Write-Host "166. Disable Windows Time Service"
      Write-Host "167. Enable Windows Time Service"
      Write-Host "168. Disable Windows Update Medic Service"
      Write-Host "169. Enable Windows Update Medic Service"
      Write-Host "170. Disable Windows Modules Installer Worker"
      Write-Host "171. Enable Windows Modules Installer Worker"
      Write-Host "172. Disable Windows Error Reporting Service"
      Write-Host "173. Enable Windows Error Reporting Service"
      Write-Host "174. Disable Windows Audio Service"
      Write-Host "175. Enable Windows Audio Service"
      Write-Host "176. Disable Windows Audio Endpoint Builder Service"
      Write-Host "177. Enable Windows Audio Endpoint Builder Service"
      Write-Host "178. Disable Windows Font Cache Service"
      Write-Host "179. Enable Windows Font Cache Service"
      Write-Host "180. Disable Windows Image Acquisition Service"
      Write-Host "181. Enable Windows Image Acquisition Service"
      Write-Host "182. Disable Windows Installer Service"
      Write-Host "183. Enable Windows Installer Service"
      Write-Host "184. Disable Windows Modules Installer Service"
      Write-Host "185. Enable Windows Modules Installer Service"
      Write-Host "186. Disable Windows Search Indexer Service"
      Write-Host "187. Enable Windows Search Indexer Service"
      Write-Host "188. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "189. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "190. Disable Windows Defender Antivirus Service"
      Write-Host "191. Enable Windows Defender Antivirus Service"
      Write-Host "192. Disable Windows Defender Security Center Service"
      Write-Host "193. Enable Windows Defender Security Center Service"
      Write-Host "194. Disable Windows Event Log Service"
      Write-Host "195. Enable Windows Event Log Service"
      Write-Host "196. Disable Windows Firewall Authorization Driver"
      Write-Host "197. Enable Windows Firewall Authorization Driver"
      Write-Host "198. Disable Windows Management Instrumentation Service"
      Write-Host "199. Enable Windows Management Instrumentation Service"
      Write-Host "200. Disable Windows Remote Management Service"
      Write-Host "201. Enable Windows Remote Management Service"
      Write-Host "202. Disable Windows Time Service"
      Write-Host "203. Enable Windows Time Service"
      Write-Host "204. Disable Windows Update Medic Service"
      Write-Host "205. Enable Windows Update Medic Service"
      Write-Host "206. Disable Windows Modules Installer Worker"
      Write-Host "207. Enable Windows Modules Installer Worker"
      Write-Host "208. Disable Windows Error Reporting Service"
      Write-Host "209. Enable Windows Error Reporting Service"
      Write-Host "210. Disable Windows Audio Service"
      Write-Host "211. Enable Windows Audio Service"
      Write-Host "212. Disable Windows Audio Endpoint Builder Service"
      Write-Host "213. Enable Windows Audio Endpoint Builder Service"
      Write-Host "214. Disable Windows Font Cache Service"
      Write-Host "215. Enable Windows Font Cache Service"
      Write-Host "216. Disable Windows Image Acquisition Service"
      Write-Host "217. Enable Windows Image Acquisition Service"
      Write-Host "218. Disable Windows Installer Service"
      Write-Host "219. Enable Windows Installer Service"
      Write-Host "220. Disable Windows Modules Installer Service"
      Write-Host "221. Enable Windows Modules Installer Service"
      Write-Host "222. Disable Windows Search Indexer Service"
      Write-Host "223. Enable Windows Search Indexer Service"
      Write-Host "224. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "225. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "226. Disable Windows Defender Antivirus Service"
      Write-Host "227. Enable Windows Defender Antivirus Service"
      Write-Host "228. Disable Windows Defender Security Center Service"
      Write-Host "229. Enable Windows Defender Security Center Service"
      Write-Host "230. Disable Windows Event Log Service"
      Write-Host "231. Enable Windows Event Log Service"
      Write-Host "232. Disable Windows Firewall Authorization Driver"
      Write-Host "233. Enable Windows Firewall Authorization Driver"
      Write-Host "234. Disable Windows Management Instrumentation Service"
      Write-Host "235. Enable Windows Management Instrumentation Service"
      Write-Host "236. Disable Windows Remote Management Service"
      Write-Host "237. Enable Windows Remote Management Service"
      Write-Host "238. Disable Windows Time Service"
      Write-Host "239. Enable Windows Time Service"
      Write-Host "240. Disable Windows Update Medic Service"
      Write-Host "241. Enable Windows Update Medic Service"
      Write-Host "242. Disable Windows Modules Installer Worker"
      Write-Host "243. Enable Windows Modules Installer Worker"
      Write-Host "244. Disable Windows Error Reporting Service"
      Write-Host "245. Enable Windows Error Reporting Service"
      Write-Host "246. Disable Windows Audio Service"
      Write-Host "247. Enable Windows Audio Service"
      Write-Host "248. Disable Windows Audio Endpoint Builder Service"
      Write-Host "249. Enable Windows Audio Endpoint Builder Service"
      Write-Host "250. Disable Windows Font Cache Service"
      Write-Host "251. Enable Windows Font Cache Service"
      Write-Host "252. Disable Windows Image Acquisition Service"
      Write-Host "253. Enable Windows Image Acquisition Service"
      Write-Host "254. Disable Windows Installer Service"
      Write-Host "255. Enable Windows Installer Service"
      Write-Host "256. Disable Windows Modules Installer Service"
      Write-Host "257. Enable Windows Modules Installer Service"
      Write-Host "258. Disable Windows Search Indexer Service"
      Write-Host "259. Enable Windows Search Indexer Service"
      Write-Host "260. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "261. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "262. Disable Windows Defender Antivirus Service"
      Write-Host "263. Enable Windows Defender Antivirus Service"
      Write-Host "264. Disable Windows Defender Security Center Service"
      Write-Host "265. Enable Windows Defender Security Center Service"
      Write-Host "266. Disable Windows Event Log Service"
      Write-Host "267. Enable Windows Event Log Service"
      Write-Host "268. Disable Windows Firewall Authorization Driver"
      Write-Host "269. Enable Windows Firewall Authorization Driver"
      Write-Host "270. Disable Windows Management Instrumentation Service"
      Write-Host "271. Enable Windows Management Instrumentation Service"
      Write-Host "272. Disable Windows Remote Management Service"
      Write-Host "273. Enable Windows Remote Management Service"
      Write-Host "274. Disable Windows Time Service"
      Write-Host "275. Enable Windows Time Service"
      Write-Host "276. Disable Windows Update Medic Service"
      Write-Host "277. Enable Windows Update Medic Service"
      Write-Host "278. Disable Windows Modules Installer Worker"
      Write-Host "279. Enable Windows Modules Installer Worker"
      Write-Host "280. Disable Windows Error Reporting Service"
      Write-Host "281. Enable Windows Error Reporting Service"
      Write-Host "282. Disable Windows Audio Service"
      Write-Host "283. Enable Windows Audio Service"
      Write-Host "284. Disable Windows Audio Endpoint Builder Service"
      Write-Host "285. Enable Windows Audio Endpoint Builder Service"
      Write-Host "286. Disable Windows Font Cache Service"
      Write-Host "287. Enable Windows Font Cache Service"
      Write-Host "288. Disable Windows Image Acquisition Service"
      Write-Host "289. Enable Windows Image Acquisition Service"
      Write-Host "290. Disable Windows Installer Service"
      Write-Host "291. Enable Windows Installer Service"
      Write-Host "292. Disable Windows Modules Installer Service"
      Write-Host "293. Enable Windows Modules Installer Service"
      Write-Host "294. Disable Windows Search Indexer Service"
      Write-Host "295. Enable Windows Search Indexer Service"
      Write-Host "296. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "297. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "298. Disable Windows Defender Antivirus Service"
      Write-Host "299. Enable Windows Defender Antivirus Service"
      Write-Host "300. Disable Windows Defender Security Center Service"
      Write-Host "301. Enable Windows Defender Security Center Service"
      Write-Host "302. Disable Windows Event Log Service"
      Write-Host "303. Enable Windows Event Log Service"
      Write-Host "304. Disable Windows Firewall Authorization Driver"
      Write-Host "305. Enable Windows Firewall Authorization Driver"
      Write-Host "306. Disable Windows Management Instrumentation Service"
      Write-Host "307. Enable Windows Management Instrumentation Service"
      Write-Host "308. Disable Windows Remote Management Service"
      Write-Host "309. Enable Windows Remote Management Service"
      Write-Host "310. Disable Windows Time Service"
      Write-Host "311. Enable Windows Time Service"
      Write-Host "312. Disable Windows Update Medic Service"
      Write-Host "313. Enable Windows Update Medic Service"
      Write-Host "314. Disable Windows Modules Installer Worker"
      Write-Host "315. Enable Windows Modules Installer Worker"
      Write-Host "316. Disable Windows Error Reporting Service"
      Write-Host "317. Enable Windows Error Reporting Service"
      Write-Host "318. Disable Windows Audio Service"
      Write-Host "319. Enable Windows Audio Service"
      Write-Host "320. Disable Windows Audio Endpoint Builder Service"
      Write-Host "321. Enable Windows Audio Endpoint Builder Service"
      Write-Host "322. Disable Windows Font Cache Service"
      Write-Host "323. Enable Windows Font Cache Service"
      Write-Host "324. Disable Windows Image Acquisition Service"
      Write-Host "325. Enable Windows Image Acquisition Service"
      Write-Host "326. Disable Windows Installer Service"
      Write-Host "327. Enable Windows Installer Service"
      Write-Host "328. Disable Windows Modules Installer Service"
      Write-Host "329. Enable Windows Modules Installer Service"
      Write-Host "330. Disable Windows Search Indexer Service"
      Write-Host "331. Enable Windows Search Indexer Service"
      Write-Host "332. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "333. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "334. Disable Windows Defender Antivirus Service"
      Write-Host "335. Enable Windows Defender Antivirus Service"
      Write-Host "336. Disable Windows Defender Security Center Service"
      Write-Host "337. Enable Windows Defender Security Center Service"
      Write-Host "338. Disable Windows Event Log Service"
      Write-Host "339. Enable Windows Event Log Service"
      Write-Host "340. Disable Windows Firewall Authorization Driver"
      Write-Host "341. Enable Windows Firewall Authorization Driver"
      Write-Host "342. Disable Windows Management Instrumentation Service"
      Write-Host "343. Enable Windows Management Instrumentation Service"
      Write-Host "344. Disable Windows Remote Management Service"
      Write-Host "345. Enable Windows Remote Management Service"
      Write-Host "346. Disable Windows Time Service"
      Write-Host "347. Enable Windows Time Service"
      Write-Host "348. Disable Windows Update Medic Service"
      Write-Host "349. Enable Windows Update Medic Service"
      Write-Host "350. Disable Windows Modules Installer Worker"
      Write-Host "351. Enable Windows Modules Installer Worker"
      Write-Host "352. Disable Windows Error Reporting Service"
      Write-Host "353. Enable Windows Error Reporting Service"
      Write-Host "354. Disable Windows Audio Service"
      Write-Host "355. Enable Windows Audio Service"
      Write-Host "356. Disable Windows Audio Endpoint Builder Service"
      Write-Host "357. Enable Windows Audio Endpoint Builder Service"
      Write-Host "358. Disable Windows Font Cache Service"
      Write-Host "359. Enable Windows Font Cache Service"
      Write-Host "360. Disable Windows Image Acquisition Service"
      Write-Host "361. Enable Windows Image Acquisition Service"
      Write-Host "362. Disable Windows Installer Service"
      Write-Host "363. Enable Windows Installer Service"
      Write-Host "364. Disable Windows Modules Installer Service"
      Write-Host "365. Enable Windows Modules Installer Service"
      Write-Host "366. Disable Windows Search Indexer Service"
      Write-Host "367. Enable Windows Search Indexer Service"
      Write-Host "368. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "369. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "370. Disable Windows Defender Antivirus Service"
      Write-Host "371. Enable Windows Defender Antivirus Service"
      Write-Host "372. Disable Windows Defender Security Center Service"
      Write-Host "373. Enable Windows Defender Security Center Service"
      Write-Host "374. Disable Windows Event Log Service"
      Write-Host "375. Enable Windows Event Log Service"
      Write-Host "376. Disable Windows Firewall Authorization Driver"
      Write-Host "377. Enable Windows Firewall Authorization Driver"
      Write-Host "378. Disable Windows Management Instrumentation Service"
      Write-Host "379. Enable Windows Management Instrumentation Service"
      Write-Host "380. Disable Windows Remote Management Service"
      Write-Host "381. Enable Windows Remote Management Service"
      Write-Host "382. Disable Windows Time Service"
      Write-Host "383. Enable Windows Time Service"
      Write-Host "384. Disable Windows Update Medic Service"
      Write-Host "385. Enable Windows Update Medic Service"
      Write-Host "386. Disable Windows Modules Installer Worker"
      Write-Host "387. Enable Windows Modules Installer Worker"
      Write-Host "388. Disable Windows Error Reporting Service"
      Write-Host "389. Enable Windows Error Reporting Service"
      Write-Host "390. Disable Windows Audio Service"
      Write-Host "391. Enable Windows Audio Service"
      Write-Host "392. Disable Windows Audio Endpoint Builder Service"
      Write-Host "393. Enable Windows Audio Endpoint Builder Service"
      Write-Host "394. Disable Windows Font Cache Service"
      Write-Host "395. Enable Windows Font Cache Service"
      Write-Host "396. Disable Windows Image Acquisition Service"
      Write-Host "397. Enable Windows Image Acquisition Service"
      Write-Host "398. Disable Windows Installer Service"
      Write-Host "399. Enable Windows Installer Service"
      Write-Host "400. Disable Windows Modules Installer Service"
      Write-Host "401. Enable Windows Modules Installer Service"
      Write-Host "402. Disable Windows Search Indexer Service"
      Write-Host "403. Enable Windows Search Indexer Service"
      Write-Host "404. Disable Windows Defender Antivirus Network Inspection Service"
      Write-Host "405. Enable Windows Defender Antivirus Network Inspection Service"
      Write-Host "406. Disable Windows Defender Antivirus Service"
      Write-Host "407. Enable Windows Defender Antivirus Service"
      Write-Host "408. Disable Windows Defender Security Center Service"
      Write-Host "409. Enable Windows Defender Security Center Service"
      Write-Host "410. Disable Windows Event Log Service"
      Write-Host "411. Enable Windows Event Log Service"
      Write-Host "412. Disable Windows Firewall Authorization Driver"
      Write-Host "413. Enable Windows Firewall Authorization Driver"
      Write-Host "414. IP Delay (Display IP every minute)"
      Write-Host "Q. Quit"
  }
  
  # Main loop
  while ($true) {
      Show-Menu
      $choice = Read-Host "Enter your choice (1-413 or Q to quit)"
      switch ($choice) {
          1 { Invoke-ForceShutdown }
          2 { Invoke-ScheduledShutdown }
          3 { Invoke-AbortShutdown }
          4 { Invoke-ForceRestart }
          5 { Invoke-ForceLogoff }
          6 { Invoke-Hibernate }
          7 { Invoke-Sleep }
          8 { Disable-PowerButton }
          9 { Enable-PowerButton }
          10 { Disable-SleepButton }
          11 { Enable-SleepButton }
          12 { Disable-Hibernation }
          13 { Enable-Hibernation }
          14 { Disable-FastStartup }
          15 { Enable-FastStartup }
          16 { Disable-USBPorts }
          17 { Enable-USBPorts }
          18 { Disable-WiFi }
          19 { Enable-WiFi }
          20 { Disable-Bluetooth }
          21 { Enable-Bluetooth }
          22 { Disable-NetworkAdapters }
          23 { Enable-NetworkAdapters }
          24 { Disable-Firewall }
          25 { Enable-Firewall }
          26 { Disable-WindowsDefender }
          27 { Enable-WindowsDefender }
          28 { Disable-WindowsUpdate }
          29 { Enable-WindowsUpdate }
          30 { Disable-TaskManager }
          31 { Enable-TaskManager }
          32 { Disable-RegistryEditor }
          33 { Enable-RegistryEditor }
          34 { Disable-CommandPrompt }
          35 { Enable-CommandPrompt }
          36 { Disable-PowerShell }
          37 { Enable-PowerShell }
          38 { Disable-RemoteDesktop }
          39 { Enable-RemoteDesktop }
          40 { Disable-AutoPlay }
          41 { Enable-AutoPlay }
          42 { Disable-Cortana }
          43 { Enable-Cortana }
          44 { Disable-Telemetry }
          45 { Enable-Telemetry }
          46 { Disable-ErrorReporting }
          47 { Enable-ErrorReporting }
          48 { Disable-WindowsSearch }
          49 { Enable-WindowsSearch }
          50 { Disable-PrintSpooler }
          51 { Enable-PrintSpooler }
          52 { Disable-RemoteRegistry }
          53 { Enable-RemoteRegistry }
          54 { Disable-WindowsDefenderFirewallService }
          55 { Enable-WindowsDefenderFirewallService }
          56 { Disable-WindowsUpdateService }
          57 { Enable-WindowsUpdateService }
          58 { Disable-BITS }
          59 { Enable-BITS }
          60 { Disable-Superfetch }
          61 { Enable-Superfetch }
          62 { Disable-WindowsTimeService }
          63 { Enable-WindowsTimeService }
          64 { Disable-WindowsErrorReportingService }
          65 { Enable-WindowsErrorReportingService }
          66 { Disable-WindowsAudioService }
          67 { Enable-WindowsAudioService }
          68 { Disable-WindowsAudioEndpointBuilderService }
          69 { Enable-WindowsAudioEndpointBuilderService }
          70 { Disable-WindowsFontCacheService }
          71 { Enable-WindowsFontCacheService }
          72 { Disable-WindowsImageAcquisitionService }
          73 { Enable-WindowsImageAcquisitionService }
          74 { Disable-WindowsInstallerService }
          75 { Enable-WindowsInstallerService }
          76 { Disable-WindowsModulesInstallerService }
          77 { Enable-WindowsModulesInstallerService }
          78 { Disable-WindowsSearchIndexerService }
          79 { Enable-WindowsSearchIndexerService }
          80 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          81 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          82 { Disable-WindowsDefenderAntivirusService }
          83 { Enable-WindowsDefenderAntivirusService }
          84 { Disable-WindowsDefenderSecurityCenterService }
          85 { Enable-WindowsDefenderSecurityCenterService }
          86 { Disable-WindowsEventLogService }
          87 { Enable-WindowsEventLogService }
          88 { Disable-WindowsFirewallAuthorizationDriver }
          89 { Enable-WindowsFirewallAuthorizationDriver }
          90 { Disable-WindowsManagementInstrumentationService }
          91 { Enable-WindowsManagementInstrumentationService }
          92 { Disable-WindowsRemoteManagementService }
          93 { Enable-WindowsRemoteManagementService }
          94 { Disable-WindowsTimeService }
          95 { Enable-WindowsTimeService }
          96 { Disable-WindowsUpdateMedicService }
          97 { Enable-WindowsUpdateMedicService }
          98 { Disable-WindowsModulesInstallerWorker }
          99 { Enable-WindowsModulesInstallerWorker }
          100 { Disable-WindowsErrorReportingService }
          101 { Enable-WindowsErrorReportingService }
          102 { Disable-WindowsAudioService }
          103 { Enable-WindowsAudioService }
          104 { Disable-WindowsAudioEndpointBuilderService }
          105 { Enable-WindowsAudioEndpointBuilderService }
          106 { Disable-WindowsFontCacheService }
          107 { Enable-WindowsFontCacheService }
          108 { Disable-WindowsImageAcquisitionService }
          109 { Enable-WindowsImageAcquisitionService }
          110 { Disable-WindowsInstallerService }
          111 { Enable-WindowsInstallerService }
          112 { Disable-WindowsModulesInstallerService }
          113 { Enable-WindowsModulesInstallerService }
          114 { Disable-WindowsSearchIndexerService }
          115 { Enable-WindowsSearchIndexerService }
          116 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          117 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          118 { Disable-WindowsDefenderAntivirusService }
          119 { Enable-WindowsDefenderAntivirusService }
          120 { Disable-WindowsDefenderSecurityCenterService }
          121 { Enable-WindowsDefenderSecurityCenterService }
          122 { Disable-WindowsEventLogService }
          123 { Enable-WindowsEventLogService }
          124 { Disable-WindowsFirewallAuthorizationDriver }
          125 { Enable-WindowsFirewallAuthorizationDriver }
          126 { Disable-WindowsManagementInstrumentationService }
          127 { Enable-WindowsManagementInstrumentationService }
          128 { Disable-WindowsRemoteManagementService }
          129 { Enable-WindowsRemoteManagementService }
          130 { Disable-WindowsTimeService }
          131 { Enable-WindowsTimeService }
          132 { Disable-WindowsUpdateMedicService }
          133 { Enable-WindowsUpdateMedicService }
          134 { Disable-WindowsModulesInstallerWorker }
          135 { Enable-WindowsModulesInstallerWorker }
          136 { Disable-WindowsErrorReportingService }
          137 { Enable-WindowsErrorReportingService }
          138 { Disable-WindowsAudioService }
          139 { Enable-WindowsAudioService }
          140 { Disable-WindowsAudioEndpointBuilderService }
          141 { Enable-WindowsAudioEndpointBuilderService }
          142 { Disable-WindowsFontCacheService }
          143 { Enable-WindowsFontCacheService }
          144 { Disable-WindowsImageAcquisitionService }
          145 { Enable-WindowsImageAcquisitionService }
          146 { Disable-WindowsInstallerService }
          147 { Enable-WindowsInstallerService }
          148 { Disable-WindowsModulesInstallerService }
          149 { Enable-WindowsModulesInstallerService }
          150 { Disable-WindowsSearchIndexerService }
          151 { Enable-WindowsSearchIndexerService }
          152 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          153 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          154 { Disable-WindowsDefenderAntivirusService }
          155 { Enable-WindowsDefenderAntivirusService }
          156 { Disable-WindowsDefenderSecurityCenterService }
          157 { Enable-WindowsDefenderSecurityCenterService }
          158 { Disable-WindowsEventLogService }
          159 { Enable-WindowsEventLogService }
          160 { Disable-WindowsFirewallAuthorizationDriver }
          161 { Enable-WindowsFirewallAuthorizationDriver }
          162 { Disable-WindowsManagementInstrumentationService }
          163 { Enable-WindowsManagementInstrumentationService }
          164 { Disable-WindowsRemoteManagementService }
          165 { Enable-WindowsRemoteManagementService }
          166 { Disable-WindowsTimeService }
          167 { Enable-WindowsTimeService }
          168 { Disable-WindowsUpdateMedicService }
          169 { Enable-WindowsUpdateMedicService }
          170 { Disable-WindowsModulesInstallerWorker }
          171 { Enable-WindowsModulesInstallerWorker }
          172 { Disable-WindowsErrorReportingService }
          173 { Enable-WindowsErrorReportingService }
          174 { Disable-WindowsAudioService }
          175 { Enable-WindowsAudioService }
          176 { Disable-WindowsAudioEndpointBuilderService }
          177 { Enable-WindowsAudioEndpointBuilderService }
          178 { Disable-WindowsFontCacheService }
          179 { Enable-WindowsFontCacheService }
          180 { Disable-WindowsImageAcquisitionService }
          181 { Enable-WindowsImageAcquisitionService }
          182 { Disable-WindowsInstallerService }
          183 { Enable-WindowsInstallerService }
          184 { Disable-WindowsModulesInstallerService }
          185 { Enable-WindowsModulesInstallerService }
          186 { Disable-WindowsSearchIndexerService }
          187 { Enable-WindowsSearchIndexerService }
          188 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          189 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          190 { Disable-WindowsDefenderAntivirusService }
          191 { Enable-WindowsDefenderAntivirusService }
          192 { Disable-WindowsDefenderSecurityCenterService }
          193 { Enable-WindowsDefenderSecurityCenterService }
          194 { Disable-WindowsEventLogService }
          195 { Enable-WindowsEventLogService }
          196 { Disable-WindowsFirewallAuthorizationDriver }
          197 { Enable-WindowsFirewallAuthorizationDriver }
          198 { Disable-WindowsManagementInstrumentationService }
          199 { Enable-WindowsManagementInstrumentationService }
          200 { Disable-WindowsRemoteManagementService }
          201 { Enable-WindowsRemoteManagementService }
          202 { Disable-WindowsTimeService }
          203 { Enable-WindowsTimeService }
          204 { Disable-WindowsUpdateMedicService }
          205 { Enable-WindowsUpdateMedicService }
          206 { Disable-WindowsModulesInstallerWorker }
          207 { Enable-WindowsModulesInstallerWorker }
          208 { Disable-WindowsErrorReportingService }
          209 { Enable-WindowsErrorReportingService }
          210 { Disable-WindowsAudioService }
          211 { Enable-WindowsAudioService }
          212 { Disable-WindowsAudioEndpointBuilderService }
          213 { Enable-WindowsAudioEndpointBuilderService }
          214 { Disable-WindowsFontCacheService }
          215 { Enable-WindowsFontCacheService }
          216 { Disable-WindowsImageAcquisitionService }
          217 { Enable-WindowsImageAcquisitionService }
          218 { Disable-WindowsInstallerService }
          219 { Enable-WindowsInstallerService }
          220 { Disable-WindowsModulesInstallerService }
          221 { Enable-WindowsModulesInstallerService }
          222 { Disable-WindowsSearchIndexerService }
          223 { Enable-WindowsSearchIndexerService }
          224 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          225 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          226 { Disable-WindowsDefenderAntivirusService }
          227 { Enable-WindowsDefenderAntivirusService }
          228 { Disable-WindowsDefenderSecurityCenterService }
          229 { Enable-WindowsDefenderSecurityCenterService }
          230 { Disable-WindowsEventLogService }
          231 { Enable-WindowsEventLogService }
          232 { Disable-WindowsFirewallAuthorizationDriver }
          233 { Enable-WindowsFirewallAuthorizationDriver }
          234 { Disable-WindowsManagementInstrumentationService }
          235 { Enable-WindowsManagementInstrumentationService }
          236 { Disable-WindowsRemoteManagementService }
          237 { Enable-WindowsRemoteManagementService }
          238 { Disable-WindowsTimeService }
          239 { Enable-WindowsTimeService }
          240 { Disable-WindowsUpdateMedicService }
          241 { Enable-WindowsUpdateMedicService }
          242 { Disable-WindowsModulesInstallerWorker }
          243 { Enable-WindowsModulesInstallerWorker }
          244 { Disable-WindowsErrorReportingService }
          245 { Enable-WindowsErrorReportingService }
          246 { Disable-WindowsAudioService }
          247 { Enable-WindowsAudioService }
          248 { Disable-WindowsAudioEndpointBuilderService }
          249 { Enable-WindowsAudioEndpointBuilderService }
          250 { Disable-WindowsFontCacheService }
          251 { Enable-WindowsFontCacheService }
          252 { Disable-WindowsImageAcquisitionService }
          253 { Enable-WindowsImageAcquisitionService }
          254 { Disable-WindowsInstallerService }
          255 { Enable-WindowsInstallerService }
          256 { Disable-WindowsModulesInstallerService }
          257 { Enable-WindowsModulesInstallerService }
          258 { Disable-WindowsSearchIndexerService }
          259 { Enable-WindowsSearchIndexerService }
          260 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          261 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          262 { Disable-WindowsDefenderAntivirusService }
          263 { Enable-WindowsDefenderAntivirusService }
          264 { Disable-WindowsDefenderSecurityCenterService }
          265 { Enable-WindowsDefenderSecurityCenterService }
          266 { Disable-WindowsEventLogService }
          267 { Enable-WindowsEventLogService }
          268 { Disable-WindowsFirewallAuthorizationDriver }
          269 { Enable-WindowsFirewallAuthorizationDriver }
          270 { Disable-WindowsManagementInstrumentationService }
          271 { Enable-WindowsManagementInstrumentationService }
          272 { Disable-WindowsRemoteManagementService }
          273 { Enable-WindowsRemoteManagementService }
          274 { Disable-WindowsTimeService }
          275 { Enable-WindowsTimeService }
          276 { Disable-WindowsUpdateMedicService }
          277 { Enable-WindowsUpdateMedicService }
          278 { Disable-WindowsModulesInstallerWorker }
          279 { Enable-WindowsModulesInstallerWorker }
          280 { Disable-WindowsErrorReportingService }
          281 { Enable-WindowsErrorReportingService }
          282 { Disable-WindowsAudioService }
          283 { Enable-WindowsAudioService }
          284 { Disable-WindowsAudioEndpointBuilderService }
          285 { Enable-WindowsAudioEndpointBuilderService }
          286 { Disable-WindowsFontCacheService }
          287 { Enable-WindowsFontCacheService }
          288 { Disable-WindowsImageAcquisitionService }
          289 { Enable-WindowsImageAcquisitionService }
          290 { Disable-WindowsInstallerService }
          291 { Enable-WindowsInstallerService }
          292 { Disable-WindowsModulesInstallerService }
          293 { Enable-WindowsModulesInstallerService }
          294 { Disable-WindowsSearchIndexerService }
          295 { Enable-WindowsSearchIndexerService }
          296 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          297 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          298 { Disable-WindowsDefenderAntivirusService }
          299 { Enable-WindowsDefenderAntivirusService }
          300 { Disable-WindowsDefenderSecurityCenterService }
          301 { Enable-WindowsDefenderSecurityCenterService }
          302 { Disable-WindowsEventLogService }
          303 { Enable-WindowsEventLogService }
          304 { Disable-WindowsFirewallAuthorizationDriver }
          305 { Enable-WindowsFirewallAuthorizationDriver }
          306 { Disable-WindowsManagementInstrumentationService }
          307 { Enable-WindowsManagementInstrumentationService }
          308 { Disable-WindowsRemoteManagementService }
          309 { Enable-WindowsRemoteManagementService }
          310 { Disable-WindowsTimeService }
          311 { Enable-WindowsTimeService }
          312 { Disable-WindowsUpdateMedicService }
          313 { Enable-WindowsUpdateMedicService }
          314 { Disable-WindowsModulesInstallerWorker }
          315 { Enable-WindowsModulesInstallerWorker }
          316 { Disable-WindowsErrorReportingService }
          317 { Enable-WindowsErrorReportingService }
          318 { Disable-WindowsAudioService }
          319 { Enable-WindowsAudioService }
          320 { Disable-WindowsAudioEndpointBuilderService }
          321 { Enable-WindowsAudioEndpointBuilderService }
          322 { Disable-WindowsFontCacheService }
          323 { Enable-WindowsFontCacheService }
          324 { Disable-WindowsImageAcquisitionService }
          325 { Enable-WindowsImageAcquisitionService }
          326 { Disable-WindowsInstallerService }
          327 { Enable-WindowsInstallerService }
          328 { Disable-WindowsModulesInstallerService }
          329 { Enable-WindowsModulesInstallerService }
          330 { Disable-WindowsSearchIndexerService }
          331 { Enable-WindowsSearchIndexerService }
          332 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          333 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          334 { Disable-WindowsDefenderAntivirusService }
          335 { Enable-WindowsDefenderAntivirusService }
          336 { Disable-WindowsDefenderSecurityCenterService }
          337 { Enable-WindowsDefenderSecurityCenterService }
          338 { Disable-WindowsEventLogService }
          339 { Enable-WindowsEventLogService }
          340 { Disable-WindowsFirewallAuthorizationDriver }
          341 { Enable-WindowsFirewallAuthorizationDriver }
          342 { Disable-WindowsManagementInstrumentationService }
          343 { Enable-WindowsManagementInstrumentationService }
          344 { Disable-WindowsRemoteManagementService }
          345 { Enable-WindowsRemoteManagementService }
          346 { Disable-WindowsTimeService }
          347 { Enable-WindowsTimeService }
          348 { Disable-WindowsUpdateMedicService }
          349 { Enable-WindowsUpdateMedicService }
          350 { Disable-WindowsModulesInstallerWorker }
          351 { Enable-WindowsModulesInstallerWorker }
          352 { Disable-WindowsErrorReportingService }
          353 { Enable-WindowsErrorReportingService }
          354 { Disable-WindowsAudioService }
          355 { Enable-WindowsAudioService }
          356 { Disable-WindowsAudioEndpointBuilderService }
          357 { Enable-WindowsAudioEndpointBuilderService }
          358 { Disable-WindowsFontCacheService }
          359 { Enable-WindowsFontCacheService }
          360 { Disable-WindowsImageAcquisitionService }
          361 { Enable-WindowsImageAcquisitionService }
          362 { Disable-WindowsInstallerService }
          363 { Enable-WindowsInstallerService }
          364 { Disable-WindowsModulesInstallerService }
          365 { Enable-WindowsModulesInstallerService }
          366 { Disable-WindowsSearchIndexerService }
          367 { Enable-WindowsSearchIndexerService }
          368 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          369 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          370 { Disable-WindowsDefenderAntivirusService }
          371 { Enable-WindowsDefenderAntivirusService }
          372 { Disable-WindowsDefenderSecurityCenterService }
          373 { Enable-WindowsDefenderSecurityCenterService }
          374 { Disable-WindowsEventLogService }
          375 { Enable-WindowsEventLogService }
          376 { Disable-WindowsFirewallAuthorizationDriver }
          377 { Enable-WindowsFirewallAuthorizationDriver }
          378 { Disable-WindowsManagementInstrumentationService }
          379 { Enable-WindowsManagementInstrumentationService }
          380 { Disable-WindowsRemoteManagementService }
          381 { Enable-WindowsRemoteManagementService }
          382 { Disable-WindowsTimeService }
          383 { Enable-WindowsTimeService }
          384 { Disable-WindowsUpdateMedicService }
          385 { Enable-WindowsUpdateMedicService }
          386 { Disable-WindowsModulesInstallerWorker }
          387 { Enable-WindowsModulesInstallerWorker }
          388 { Disable-WindowsErrorReportingService }
          389 { Enable-WindowsErrorReportingService }
          390 { Disable-WindowsAudioService }
          391 { Enable-WindowsAudioService }
          392 { Disable-WindowsAudioEndpointBuilderService }
          393 { Enable-WindowsAudioEndpointBuilderService }
          394 { Disable-WindowsFontCacheService }
          395 { Enable-WindowsFontCacheService }
          396 { Disable-WindowsImageAcquisitionService }
          397 { Enable-WindowsImageAcquisitionService }
          398 { Disable-WindowsInstallerService }
          399 { Enable-WindowsInstallerService }
          400 { Disable-WindowsModulesInstallerService }
          401 { Enable-WindowsModulesInstallerService }
          402 { Disable-WindowsSearchIndexerService }
          403 { Enable-WindowsSearchIndexerService }
          404 { Disable-WindowsDefenderAntivirusNetworkInspectionService }
          405 { Enable-WindowsDefenderAntivirusNetworkInspectionService }
          406 { Disable-WindowsDefenderAntivirusService }
          407 { Enable-WindowsDefenderAntivirusService }
          408 { Disable-WindowsDefenderSecurityCenterService }
          409 { Enable-WindowsDefenderSecurityCenterService }
          410 { Disable-WindowsEventLogService }
          411 { Enable-WindowsEventLogService }
          412 { Disable-WindowsFirewallAuthorizationDriver }
          413 { Enable-WindowsFirewallAuthorizationDriver }
          415 { Start-IPDelay }
          "Q" { exit }
          default { Write-Host "Invalid choice. Please try again." }
      }
      Read-Host "Press Enter to continue..."
  }
