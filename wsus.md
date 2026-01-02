### Scripts to import manual download cab / KB into c:\wsus\wsuscontent
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
reg add HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319 /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
iisreset
Restart-Service WSUSService
Start-Sleep -Seconds 10

$updateId = "da327f7c-5d64-43dc-9671-72723a5074f3"
$wsus = Get-WsusServer
$subscription = $wsus.GetSubscription()

# Start synchronization to establish connection
Write-Host "Starting synchronization to establish connection..."
$subscription.StartSynchronization()

# Wait a few seconds for connection to establish
Start-Sleep -Seconds 5

# Now cancel it so it doesn't download everything
Write-Host "Stopping synchronization..."
$subscription.StopSynchronization()

# Check if it's stopped
Start-Sleep -Seconds 2
$status = $subscription.GetSynchronizationStatus()
Write-Host "Sync status: $status"

# Now try your import
Write-Host "`nAttempting import..."

try {
    $wsus.ImportUpdateFromCatalogSite($updateId, @())
    Write-Host "Import successful!"
} catch {
    Write-Host "Import failed: $($_.Exception.Message)"
}

# (Get-WsusServer).SearchUpdate('KbNumber') to check if the KB exist
```
#
### Sync WSUS
```
How WSUS Actually Works:
Method 1: Automatic Sync (Recommended)

# WSUS downloads updates automatically from Microsoft
$WSUSServer = Get-WsusServer
$subscription = $WSUSServer.GetSubscription()

# Start sync - WSUS will download all approved updates automatically
$subscription.StartSynchronization()

# Check what updates are available after sync
Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.KnowledgebaseArticles -contains "5068791"}

Two Ways WSUS Gets Updates:
1. Automatic Synchronization (Normal Way):

WSUS connects to Microsoft Update
Downloads metadata and update files automatically
You just approve/decline what you want to deploy
No manual MSU downloads needed
2. Manual Import (Only for Special Cases):

For updates not available through normal sync
For offline environments
For custom/third-party updates
This is what you were trying to do with the MSU
Configure WSUS to Sync Automatically:
1. Check current sync settings:

$WSUSServer = Get-WsusServer
$subscription = $WSUSServer.GetSubscription()
$subscription.GetSubscriptionProperties()

2. Configure automatic sync:

# Set sync schedule (daily at 3 AM)
$subscription.SynchronizeAutomatically = $true
$subscription.SynchronizeAutomaticallyTimeOfDay = (New-TimeSpan -Hours 3)
$subscription.NumberOfSynchronizationsPerDay = 1
$subscription.Save()

3. Manual sync right now:

$subscription.StartSynchronization()

Normal WSUS Workflow:
WSUS syncs with Microsoft (automatically downloads updates)
You review available updates in WSUS console
You approve updates for deployment
Client computers download from your WSUS server
Check if KB5068791 is Available via Sync:
# After sync completes, search for your update
$WSUSServer = Get-WsusServer
$Update = Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.KnowledgebaseArticles -contains "5068791"}

if ($Update) {
    Write-Host "Found: $($Update.Title)"
    Write-Host "Classification: $($Update.Classification)"
    
    # Approve it for deployment
    $Update | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
} else {
    Write-Host "Update not available through sync - may need manual import"
}

Summary:
Normal process: WSUS syncs → You approve → Clients install
Manual MSU: Only needed for special cases or offline scenarios
Your situation: Try sync first, manual import only if the update isn't available through normal channels
You can delete that corrupted MSU file and just let WSUS sync normally. Much easier!

# Clean up the manual MSU file
Remove-Item "C:\WSUS\WsusContent\windows10.0-kb5068791-x64_a8b1b1b6c7b6b673c5a5f32772749eb2bb80c88b.msu" -Force

# Let WSUS do its job automatically
$WSUSServer = Get-WsusServer
$WSUSServer.GetSubscription().StartSynchronization()
```
### Recommended Steps:
```
1. First, try WSUSUTIL import:

cd "C:\Program Files\Update Services\Tools"
wsusutil.exe import "C:\WSUS\WsusContent\windows10.0-kb5068791-x64_a8b1b1b6c7b6b673c5a5f32772749eb2bb80c88b.msu" "C:\temp\import.log"

2. Check the import log:

Get-Content "C:\temp\import.log"

3. Verify the import worked:

$WSUSServer = Get-WsusServer
$Update = Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.KnowledgebaseArticles -contains "5068791"}

if ($Update) {
    Write-Host "SUCCESS: Update imported - $($Update.Title)"
    # Approve it
    $Update | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
} else {
    Write-Host "Import failed - check import.log for errors"
}
```
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

### On Windows Server with WSUS role
Import-Module UpdateServices

2. Connect to WSUS Server:

$WSUSServer = Get-WsusServer -Name "wsus.davidawcloudsecurity" -PortNumber 8530

3. Approve Specific KB Updates:

### Get a specific KB update
$Update = Get-WsusUpdate -UpdateServer $WSUSServer | Where-Object {$_.KnowledgebaseArticles -contains "KB5034441"}

### Approve for installation to all computers
$Update | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

### Approve for a specific computer group
$Update | Approve-WsusUpdate -Action Install -TargetGroupName "Production Servers"

4. Approve Multiple Security Updates:

### Get all unapproved security updates
$SecurityUpdates = Get-WsusUpdate -UpdateServer $WSUSServer -Classification "Security Updates" -Approval "Unapproved"

### Approve all security updates for installation
$SecurityUpdates | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

5. Approve Updates by Title Pattern:

### Approve all Windows 11 security updates
```
Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {$_.Title -like "*Windows 11*" -and $_.Classification -eq "Security Updates"} | 
Approve-WsusUpdate -Action Install -TargetGroupName "Windows 11 Computers"
```
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

### Approve all security and critical updates released in the last 30 days
```
$LastMonth = (Get-Date).AddDays(-30)
Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {
    ($_.Classification -eq "Security Updates" -or $_.Classification -eq "Critical Updates") -and
    $_.CreationDate -gt $LastMonth -and
    $_.IsApproved -eq $false
} | 
Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

These PowerShell commands give you comprehensive control over WSUS update management and client configuration. The WSUS PowerShell module provides the most robust way to manage updates on the server side.

How to Import MSU into WSUS
Method 1: WSUS Console (GUI)

Open WSUS Administration Console:

Server Manager → Tools → Windows Server Update Services
Import the Update:

Right-click on "Updates" in the left pane
Select "Import Updates..."
Browse and select your MSU file
Click "Next" and follow the wizard
Approve the Update:

Navigate to Updates → All Updates
Find your imported update
Right-click → Approve
Select target computer groups
Choose "Approved for Install"
```
### Method 2: Import the MSU file into WSUS
$WSUSServer = Get-WsusServer -Name "wsus.davidawcloudsecurity" -PortNumber 8530

### Import the update
Import-WsusUpdate -UpdateServer $WSUSServer -MsuPath "C:\path\to\your\update.msu"

### Find and approve the imported update
$ImportedUpdate = Get-WsusUpdate -UpdateServer $WSUSServer | 
    Where-Object {$_.KnowledgebaseArticles -contains "KB5034441"}  # Replace with your KB

### Approve for installation
$ImportedUpdate | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"

Method 3: Using WSUS Import Tool

### Alternative import method
$WSUSServer = Get-WsusServer
$UpdateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$UpdateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved

### Import and configure
```
Add-WsusUpdate -UpdateServer $WSUSServer -Path "C:\path\to\your\update.msu"

Where WSUS Stores Updates
WSUS Content Location:

Default: C:\WSUS\WsusContent\
Updates are stored in subfolders with GUID names
You don't manually copy files here - use the import process
Check WSUS Content Location:

$WSUSServer = Get-WsusServer
$WSUSServer.GetConfiguration().LocalContentCachePath

Verify Import and Deployment
1. Check if update was imported:

Get-WsusUpdate -UpdateServer $WSUSServer | 
Where-Object {$_.Title -like "*KB5034441*"} | 
Select-Object Title, Classification, ApprovalState

2. Monitor client update status:
```
### Check which computers need the update
```
Get-WsusComputer -UpdateServer $WSUSServer | 
Get-WsusComputerUpdateStatus | 
Where-Object {$_.UpdateTitle -like "*KB5034441*"}
```
3. Force client to check for updates: On client machines, run:
```
wuauclt /detectnow
wuauclt /updatenow
```
Or in PowerShell:
```
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
```
### Best Practices
1. Test Group First:

### Create a test computer group
```
Approve updates for test group first
Monitor for issues before broader deployment
2. Staging Process:
```
### Approve for test group first
$TestUpdate | Approve-WsusUpdate -Action Install -TargetGroupName "Test Computers"

### After testing, approve for production
$TestUpdate | Approve-WsusUpdate -Action Install -TargetGroupName "Production Computers"

3. Monitor Deployment:

### Check deployment progress
```
Get-WsusUpdateApproval -UpdateServer $WSUSServer | 
Where-Object {$_.Update.KnowledgebaseArticles -contains "KB5034441"}
```
