### Check if WSUS is setup
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue
```
### Setup WSUS
```
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://your-wsus-server:8530"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://your-wsus-server:8530"
```
### Verify WSUS
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer"
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer"
```
### Restart WSUS
```
Restart-Service -Name "wuauserv"
```
WSUS Server Administration (Approving Updates)
1. Install WSUS PowerShell Module:

# On Windows Server with WSUS role
Import-Module UpdateServices

2. Connect to WSUS Server:

$WSUSServer = Get-WsusServer -Name "wsus.davidawcloudsecurity" -PortNumber 8530

3. Approve Specific KB Updates:

# Get a specific KB update
$Update = Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.KnowledgebaseArticles -contains "KB5034441"}

# Approve for installation to all computers
$Update | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

# Approve for a specific computer group
$Update | Approve-WsusUpdate -Action Install -TargetGroupName "Production Servers"

4. Approve Multiple Security Updates:

# Get all unapproved security updates
$SecurityUpdates = Get-WsusUpdate -UpdateServer $WSUSServer -Classification "Security Updates" -Approval "Unapproved"

# Approve all security updates for installation
$SecurityUpdates | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

5. Approve Updates by Title Pattern:

# Approve all Windows 11 security updates
Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {$_.Title -like "*Windows 11*" -and $_.Classification -eq "Security Updates"} | 
Approve-WsusUpdate -Action Install -TargetGroupName "Windows 11 Computers"

Client-Side Configuration
1. Configure Windows Update Settings:

# Set automatic update options
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4

# Configure installation schedule
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3

2. Force Update Detection and Installation:

# Trigger update detection
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")

# Install specific updates
$UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($Update in $SearchResult.Updates) {
    if ($Update.KBArticleIDs -contains "5034441") {  # Specific KB
        $UpdatesToInstall.Add($Update)
    }
}

if ($UpdatesToInstall.Count -gt 0) {
    $Installer = $UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallationResult = $Installer.Install()
}

Advanced WSUS Management Examples
1. Bulk Approve Updates by Category:

# Approve all critical updates
Get-WsusUpdate -UpdateServer $WSUSServer -Classification "Critical Updates" -Approval "Unapproved" | 
Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

# Approve definition updates
Get-WsusUpdate -UpdateServer $WSUSServer -Classification "Definition Updates" -Approval "Unapproved" | 
Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

2. Decline Superseded Updates:

Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.IsSuperseded -eq $true} | 
Deny-WsusUpdate

3. Create Computer Groups and Approve Updates:

# Create a new computer group
Add-WsusComputer -UpdateServer $WSUSServer -ComputerTargetGroupName "Test Servers"

# Approve updates for specific group
Get-WsusUpdate -UpdateServer $WSUSServer -Classification "Security Updates" | 
Approve-WsusUpdate -Action Install -TargetGroupName "Test Servers"

4. Get Update Approval Status:

# Check approval status of specific KB
Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {$_.KnowledgebaseArticles -contains "KB5034441"} | 
Get-WsusUpdateApproval

5. Automated Monthly Approval Script:

# Approve all security and critical updates released in the last 30 days
$LastMonth = (Get-Date).AddDays(-30)
Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {
    ($_.Classification -eq "Security Updates" -or $_.Classification -eq "Critical Updates") -and
    $_.CreationDate -gt $LastMonth -and
    $_.IsApproved -eq $false
} | 
Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

These PowerShell commands give you comprehensive control over WSUS update management and client configuration. The WSUS PowerShell module provides the most robust way to manage updates on the server side.
