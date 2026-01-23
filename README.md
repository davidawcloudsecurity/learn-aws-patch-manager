# learn-aws-patch-manager

### How to patch RHEL with cutoff date
If you want December 2025 and earlier (but not January 2026):
```
sudo dnf updateinfo list security available -v | grep -E '2025-(0[1-9]|1[0-2])'
RHSA-2025:22660 Moderate/Sec.  systemd-udev-252-55.el9_7.7.x86_64               2025-12-03 10:38:39
RHSA-2025:20945 Moderate/Sec.  vim-minimal-2:8.2.2637-23.el9_7.x86_64           2025-11-11 11:47:33
```
displays detailed information about a specific security advisory.
```
sudo dnf updateinfo info RHSA-2025:22660Updating Subscription Management repositories.Unable to read consumer identity

This system is not registered with an entitlement server. You can use "rhc" or "subscription-manager" to register.

Last metadata expiration check: 0:27:43 ago on Fri 23 Jan 2026 05:56:42 AM UTC.
===============================================================================
  Moderate: systemd security update
===============================================================================
  Update ID: RHSA-2025:22660
       Type: security
    Updated: 2025-12-03 10:38:39
       Bugs: 2369242 - CVE-2025-4598 systemd-coredump: race condition that allows a local attacker to crash a SUID program and gainread access to the resulting core dump
       CVEs: CVE-2025-4598
Description: The systemd packages contain systemd, a system and service manager for Linux, compatible with the SysV and LSB init scripts. It provides aggressive parallelism capabilities, uses socket and D-Bus activation for starting services, offers on-demand starting of daemons, and keeps track of processes using Linux cgroups. In addition, it supports snapshotting and restoring of the system state, maintains mount and automount points, and implements an elaborate transactional dependency-based service control logic. It can also work as a drop-in replacement for sysvinit.
           :
           : Security Fix(es):
           :
           : * systemd-coredump: race condition that allows a local attacker to crash a SUID program and gain read access to the resulting core dump (CVE-2025-4598)
           :
           : For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.
```

### Need to check what this does
How to get updates rhel with cutoff date like dec 2025. Get the list of year or month

You're NOT missing any security advisories themselves - sort -u correctly gives you the unique list of security bulletins.
```
sudo dnf updateinfo list security available -v | grep -E '2025-(0[1-9]|1[0-2])' | cut -d' ' -f1 | sort -u > advisories.txt
RHSA-2025:23483
```
How to install with cutoff date
```
sudo dnf update --advisory=$(cat advisories.txt | tr '\n' ',') --assumeno
```
### How to check what was installed
```
sudo dnf updateinfo list --installed | grep "2026-"
```
### All packages installed today (2026-01-23)
```
rpm -qa --last | grep "Thu 23 Jan 2026"
```
### All packages installed in January 2026
```
rpm -qa --last | grep "Jan 2026"
```
### All packages from 2025
```
rpm -qa --last | grep "2025"
```
Function Force-WSUSCheckin($Computer)
{
   Invoke-Command -computername $Computer -scriptblock { Start-Service wuauserv -Verbose }
   # Have to use psexec with the -s parameter as otherwise we receive an "Access denied" message loading the comobject
   $Cmd = '$updateSession = new-object -com "Microsoft.Update.Session";$updates=$updateSession.CreateupdateSearcher().Search($criteria).Updates'
   &amp; c:\bin\psexec.exe -s \\$Computer powershell.exe -command $Cmd
   Write-host "Waiting 10 seconds for SyncUpdates webservice to complete to add to the wuauserv queue so that it can be reported on"
   Start-sleep -seconds 10
   Invoke-Command -computername $Computer -scriptblock
   {
      # Now that the system is told it CAN report in, run every permutation of commands to actually trigger the report in operation
      wuauclt /detectnow
      (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
      wuauclt /reportnow
      c:\windows\system32\UsoClient.exe startscan
   }
}
```

### How to import KB into WSUS with guild and manual downloaded msu
```
https://rdr-it.com/en/wsus-manually-import-an-update-from-the-microsoft-update-catalog/
```

### How to read windowsupdatelog with guild
```
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbols-windows-update
```
### How to scan, download and install KB using WUA API
Scan for general updates
```
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates | Select-Object Title
```
Scan for security updates
```
(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates | Where-Object {($_.Categories|%{$_.Name}) -contains "Security Updates"} | Select-Object Title
```
# Last 50 Windows Update related events
```
get-winevent -logname System| Where-Object {$_.ProviderName -eq "Microsoft-Windows-WindowsUpdateClient"} | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
```

### Here are three one-liners for **Security Updates Only**:

## 1. Scan for Security Updates
```powershell
$S=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|?{($_.Categories|%{$_.Name}) -contains "Security Updates"};Write-Host "Security Updates: $($S.Count)";$S|Select Title
```
## 2. Scans and Download Security Updates
```powershell
$S=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|?{($_.Categories|%{$_.Name}) -contains "Security Updates"};if($S){$C=New-Object -ComObject Microsoft.Update.UpdateColl;$S|%{[void]$C.Add($_)};$D=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownloader();$D.Updates=$C;$D.Download();Write-Host "Downloaded Security: $($C.Count)"}else{Write-Host "No security updates"}
```
## 2.1 Scans and Install Security Updates Only
```
$S=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|?{($_.Categories|%{$_.Name}) -contains "Security Updates"};if($S){$C=New-Object -ComObject Microsoft.Update.UpdateColl;$S|%{[void]$C.Add($_)};$I=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller();$I.Updates=$C;$R=$I.Install();Write-Host "Installed: $($C.Count), Result: $($R.ResultCode)"}else{Write-Host "No security updates"}
```
## 3. Scan, Download and Install Security Updates
```powershell
$S=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates|?{($_.Categories|%{$_.Name}) -contains "Security Updates"};if($S){$C=New-Object -ComObject Microsoft.Update.UpdateColl;$S|%{[void]$C.Add($_)};$D=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateDownloader();$D.Updates=$C;$D.Download();$I=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller();$I.Updates=$C;$R=$I.Install();Write-Host "Installed: $($C.Count), Result: $($R.ResultCode)"}else{Write-Host "No security updates"}
```

Run in sequence: **Scan → Download → Install** for security updates only.

### Here are three one-liners for scan, download, and install using WUA API:

## 1. Scan for Security Updates
```
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$AllUpdates = $Searcher.Search("IsInstalled=0").Updates
$SecurityUpdates = $AllUpdates | Where-Object {($_.Categories | ForEach-Object {$_.Name}) -contains "Security Updates"}

if($SecurityUpdates.Count -gt 0){
    $UpdateColl = New-Object -ComObject Microsoft.Update.UpdateColl
    $SecurityUpdates | ForEach-Object {[void]$UpdateColl.Add($_)}
    
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $UpdateColl
    $Downloader.Download()
    
    $Installer = $Session.CreateUpdateInstaller()
    $Installer.Updates = $UpdateColl
    $Result = $Installer.Install()
    
    Write-Host "Installed $($UpdateColl.Count) security updates. Result: $($Result.ResultCode)"
}else{
    Write-Host "No security updates available"
}
```

## 1. Scan for Updates General
```powershell
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$Updates = $Searcher.Search("IsInstalled=0").Updates

$Downloader = $Session.CreateUpdateDownloader()
$Downloader.Updates = $Updates
$Downloader.Download()  # This downloads the KB files

# After downloading successfully, then install:
# Run this part as Administrator
$Installer = $Session.CreateUpdateInstaller()
$Installer.Updates = $Updates
$Installer.Install()  # This installs the already-downloaded KB files
```

Run them in sequence: **Scan → Download → Install**
### How to troubleshoot error from Windows patch
```
https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/common-windows-update-errors
https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/error-0x800f0922-installing-windows-updates?source=recommendations
https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/fix-windows-update-errors#common-corruption-errors
https://repost.aws/articles/AR4VPU_937RGCwpEYpJeMImw/how-do-i-troubleshoot-and-deep-dive-windows-patching-updates-installation-failures-on-ec2-windows-instances
```
### how to download from windows catalog
```
$ProgressPreference = 'SilentlyContinue'
wget -o test.msu https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu
```
### how to install kb using dism by extracting cab first
```
expand -F:*.cab .\windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu .
Microsoft (R) File Expansion Utility
Copyright (c) Microsoft Corporation. All rights reserved.

Adding .\Windows10.0-KB5058392-x64.cab to Extraction Queue
Adding .\WSUSSCAN.cab to Extraction Queue
Adding .\SSU-17763.7313-x64.cab to Extraction Queue

Expanding Files ....
Progress: 0 out of 3 files
Expanding Files Complete ...
3 files total.
```
Install SSU first then install the main update
```
DISM /Online /Add-Package /PackagePath:"C:\temp\SSU-17763.7313-x64.cab" /quiet /norestart
DISM /Online /Add-Package /PackagePath:"C:\temp\Windows10.0-KB5058392-x64.cab" /quiet /norestart
```
### Run as job
```
Start-Job -Name "ErrorJob" -ScriptBlock { DISM /Online /Add-Package /PackagePath:"C:\temp\SSU-17763.7313-x64.cab" /quiet /norestart }
Start-Job -ScriptBlock { DISM /Online /Add-Package /PackagePath:"C:\temp\SSU-17763.7313-x64.cab" /quiet /norestart }
```
### how to uninstall KB using dism
Based on 17763.7314 I assume it should be - https://support.microsoft.com/en-au/topic/may-13-2025-kb5058392-os-build-17763-7314-e72d5090-15f1-4562-a7c0-39c1155fa01c
```
Get-WindowsPackage -Online | Where-Object {$_.PackageName -like "*17763.7314*"}
PackageName  : Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.7314.1.18
PackageState : Installed
ReleaseType  : SecurityUpdate
InstallTime  : 5/15/2025 7:34:00 PM```
```
```
DISM /Online /Remove-Package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.7314.1.18 /quiet /norestart
```
```
wget -O custom_name.zip http://example.com/file.zip
```
### How to pull names without title
```
Get-WindowsPackage -Online | Where-Object {$_.packagename -like "*17763.7434*"} | Select-Object -ExpandProperty packagename
```
### How to pull packagename where packagename contains certain KB metadata (17763.7434)
```
DISM /Online /Get-PackageInfo /PackageName:$(Get-WindowsPackage -Online | Where-Object {$_.packagename -like "*17763.7434*"} | Select-Object -Expand
Property packagename)
```
### How to pull more information especailly for cumulative updates for .net
```
DISM /Online /Get-PackageInfo /PackageName:Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.4785.1

Deployment Image Servicing and Management tool
Version: 10.0.17763.5830

Image Version: 10.0.17763.7314

Package information:

Package Identity : Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.4785.1
Applicable : Yes
Copyright : Microsoft Corporation
Company : Microsoft Corporation
Creation Time :
Description : Fix for KB5055175
Install Client : WindowsUpdateAgent
Install Package Name : Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.4785.1.mum
Install Time : 5/15/2025 3:15 AM
Last Update Time :
Name : default
Product Name : Package_for_DotNetRollup
Product Version :
Release Type : Update
Restart Required : Possible
Support Information : http://support.microsoft.com/?kbid=5055175
State : Installed
Completely offline capable : No
Self servicing package : No
Capability Identity :

Custom Properties:

(No custom properties found)

Features listing for package : Package_for_DotNetRollup~31bf3856ad364e35~amd64~~10.0.4785.1

(No features found for this package)

The operation completed successfully
```
### Monitor Windows Update Installation Logs
```
Get-WindowsUpdateLog
```
### Show what is installed
```
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
```
```
Get-HotFix | Sort-Object -Descending -Property InstalledOn
```
```
wmic qfe list
```
### Check for Pending or Missing Updates
```
(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title
```
### Force update
```
wuauclt.exe /resetauthorization /detectnow
```
resource - https://inventivehq.com/windows-update-commands-powershell-usoclient-wuauclt/

To install an `.msu` update package using **wusa** (Windows Update Standalone Installer), follow these steps:

1. **Run the wusa Command**  
   Use the following syntax:
   ```
   wusa .msu [options]
   ```
   For example, to install an update silently and prevent automatic restart:
   ```
   wusa C:\Updates\Windows10-KB123456-x64.msu /quiet /norestart
   ```
   - Replace `C:\Updates\Windows10-KB123456-x64.msu` with the full path and filename of your `.msu` file.
   - `/quiet` runs the installer without user interaction.
   - `/norestart` prevents the system from restarting automatically after installation[2][3][5].

2. **Other Useful Options**
   - `/forcerestart` - Forces an immediate restart after installation.
   - `/warnrestart:` - Warns before restarting.
   - `/logfile:` - Saves installation logs to a specified file[5].

**Example Commands:**
- Install update interactively:
  ```
  wusa C:\Updates\Windows10-KB123456-x64.msu
  ```
- Install silently, no restart:
  ```
  wusa C:\Updates\Windows10-KB123456-x64.msu /quiet /norestart
  ```
- Install and log output:
  ```
  wusa C:\Updates\Windows10-KB123456-x64.msu /quiet /logfile:C:\update_log.txt
  ```
  To discover what is available for `Get-WinEvent`, you can list all event logs and providers on your system using its built-in parameters. Here’s how:

---

## List All Event Logs

To see all the logs you can query with `Get-WinEvent`, use:

```powershell
Get-WinEvent -ListLog *
```
- This command lists every event log available on your system, including classic logs (like `System`, `Application`) and newer, application-specific or operational logs[1][3][5].

---

## List All Event Providers

To see all providers (sources of events), use:

```powershell
Get-WinEvent -ListProvider *
```
- This lists all event providers, which are sources that write events to the logs. Providers often correspond to Windows components, drivers, or applications[1][3][5].

---
https://www.pdq.com/powershell/get-winevent/
## List Events for a Specific Provider

To see what events a provider can generate (including Event IDs and descriptions):

```powershell
(Get-WinEvent -ListProvider "Microsoft-Windows-GroupPolicy").Events | Format-Table ID, Description -AutoSize
```
- Replace `"Microsoft-Windows-GroupPolicy"` with any provider name you found from the previous step[3].

---

## Summary Table

| Command                                 | Purpose                                 |
|------------------------------------------|-----------------------------------------|
| `Get-WinEvent -ListLog *`                | List all available event logs           |
| `Get-WinEvent -ListProvider *`           | List all event providers                |
| `(Get-WinEvent -ListProvider "Name").Events` | List event IDs/descriptions for provider |

---
When you run `wusa /uninstall /kb:5055519 /quiet` via SSM (or any remote PowerShell), **errors and status will not display in your console due to the `/quiet` switch**. To determine if the uninstallation failed or succeeded, you must check the appropriate Windows event logs.

---

## 1. **Where to Check for WUSA Errors**

### **A. Setup Event Log**
- **Log Location:** `Event Viewer > Windows Logs > Setup`
- **Relevant Event IDs:**  
  - **Event ID 8:** Indicates a failure when using WUSA with `/quiet` or `/norestart` (especially on newer Windows versions; see[6][10]).
  - **Other IDs:** Success or additional error details may also be logged here.

### **B. Application Event Log**
- **Log Location:** `Event Viewer > Windows Logs > Application`
- **Source:** `MsiInstaller` (for MSI-based updates, less common for Windows Updates)

---

## 2. **What to Look For**

- **Event ID 8 in Setup Log:**  
  This specifically signals that a WUSA uninstall attempt failed when run in quiet mode (no user interaction)[6][10].
- **Error Messages:**  
  The event details will include the KB number, the command line used, and an error code (e.g., `0x800f0905`, `2147549183`, etc.)[4][8].
- **Success:**  
  If the uninstall is successful, there may be a corresponding success event, but failures are more reliably logged.

---

## 3. **How to Check via PowerShell**

You can query the Setup log for recent WUSA uninstall errors:

```powershell
Get-WinEvent -LogName Setup | Where-Object {
    $_.Id -eq 8 -and $_.Message -match "5055519"
} | Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending
```
- This will show recent uninstall failures for KB5055519.

---
https://medium.com/@AhmedZia01/analyzing-windows-event-logs-with-powershell-get-winevent-b08163e78221
## 4. **Key Notes**

- **WUSA /quiet uninstall failures are common on newer Windows versions** (Windows 10/11, Server 2016/2019) and are logged as Event ID 8 in the Setup log[6][10].
- **You will not see errors in your SSM/PowerShell output** due to the `/quiet` switch.
- **Always check the Setup event log** after running silent uninstall commands with WUSA.

---

### 5. **How to schedule DISM**
```
# Create the scheduled task
$action = New-ScheduledTaskAction -Execute 'DISM.exe' -Argument '/Online /Remove-Package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~14393.8519.1.28'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Remove_KB5066836" -Action $action -Trigger $trigger -Principal $principal
# After creating the task
Start-ScheduledTask -TaskName "Remove_KB5066836"

# To monitor status
Get-ScheduledTask -TaskName "Remove_KB5066836" | Get-ScheduledTaskInfo
```
#### **Start Immediately with Process**
```
# Run directly with elevated rights
Start-Process "DISM.exe" -ArgumentList "/Online /Remove-Package /PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~14393.8519.1.28" -Wait -NoNewWindow
```

### Troubleshooting Windows Update logs
https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs

### Troubleshooting packages
https://techcommunity.microsoft.com/blog/askperf/msi-troubleshooting-package-installation/373979

### **Summary Table**

| Event Log                | Event ID | What it Means                        | Where to Find      |
|--------------------------|----------|--------------------------------------|--------------------|
| Setup                    | 8        | WUSA uninstall failed (esp. /quiet)  | Windows Logs\Setup |
| Setup/Application        | varies   | Success or other error details       | Windows Logs\Setup or Application |

---

**References:**  
- [Microsoft: WUSA event log location][1]  
- [StackOverflow: WUSA /quiet uninstall fails, Event ID 8][6][10]  
- [NinjaOne: Reading Windows Update logs][7]

---

**In summary:**  
After running `wusa /uninstall /kb:5055519 /quiet`, check the **Setup event log** for **Event ID 8** and related entries to determine if the uninstall succeeded or failed. Errors and details will be logged there, as silent mode suppresses console output.

### how to automate patching in windows and rhel with internet

Resource - https://aws.amazon.com/blogs/mt/patching-your-windows-ec2-instances-using-aws-systems-manager-patch-manager/

AWS Systems Manager (SSM) Patch Manager for Windows and RHEL critical patching, a weekly Maintenance Window, and email notifications via SNS and CloudWatch Events/EventBridge.

### Terraform Configuration Overview
1. **SNS Topic and Subscription**: For email notifications.
2. **CloudWatch Event Rule and Target**: To detect SSM patch failures and send details to SNS.
3. **SSM Patch Baselines**: For Windows and RHEL critical updates.
4. **SSM Maintenance Window**: For weekly patching.
5. **SSM Maintenance Window Task**: To execute the patching.
6. **IAM Role**: For EC2 instances to interact with SSM (assumed pre-existing for brevity).

### Terraform Code
Save this in a file like `main.tf`. Adjust variables (e.g., email address, timezone) as needed.

```hcl
provider "aws" {
  region = "us-east-1" # Adjust to your region
}

# Variables
variable "email_address" {
  description = "Email address for patch failure notifications"
  type        = string
  default     = "your.email@example.com" # Replace with your email
}

# 1. SNS Topic for Email Notifications
resource "aws_sns_topic" "patch_failure_notifications" {
  name = "PatchFailureNotifications"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.patch_failure_notifications.arn
  protocol  = "email"
  endpoint  = var.email_address
}

# 2. CloudWatch Event Rule for SSM Patch Failures
resource "aws_cloudwatch_event_rule" "ssm_patch_failure_rule" {
  name        = "SSM-PatchFailure-Rule"
  description = "Triggers on SSM patch command failures"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["EC2 Command Invocation Status Change"]
    detail = {
      status = ["Failed"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.ssm_patch_failure_rule.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.patch_failure_notifications.arn

  input_transformer {
    input_paths = {
      "instance-id"   = "$.detail.instance-id"
      "command-id"    = "$.detail.command-id"
      "status"        = "$.detail.status"
      "status-details" = "$.detail.status-details"
    }
    input_template = <<-EOF
      "Patch operation failed on instance <instance-id>. Command ID: <command-id>. Status: <status>. Details: <status-details>. Check CloudWatch Logs at /ssm/patch-logs for more details."
    EOF
  }
}

# Grant CloudWatch Events permission to publish to SNS
resource "aws_sns_topic_policy" "sns_policy" {
  arn    = aws_sns_topic.patch_failure_notifications.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.patch_failure_notifications.arn
      }
    ]
  })
}

# 3. SSM Patch Baselines
# Windows Critical Updates
resource "aws_ssm_patch_baseline" "windows_critical" {
  name             = "Critical-Windows-PatchBaseline"
  operating_system = "WINDOWS"
  approved_patches = []
  approval_rule {
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["CriticalUpdates"]
    }
    patch_filter {
      key    = "MSRC_SEVERITY"
      values = ["Critical"]
    }
    approve_after_days = 1 # Approve patches 1 day after release (post-Patch Tuesday)
  }
}

# RHEL Critical Updates
resource "aws_ssm_patch_baseline" "rhel_critical" {
  name             = "Critical-RHEL-PatchBaseline"
  operating_system = "REDHAT_ENTERPRISE_LINUX"
  approved_patches = []
  approval_rule {
    patch_filter {
      key    = "SEVERITY"
      values = ["Critical"]
    }
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }
    approve_after_days = 1
  }
}

# 4. SSM Maintenance Window (Weekly, Wednesday 2:00 AM UTC)
resource "aws_ssm_maintenance_window" "weekly_patching" {
  name              = "Weekly-Critical-Patching"
  schedule          = "cron(0 0 2 ? * WED *)" # Every Wednesday at 2:00 AM UTC
  duration          = 3                        # 3-hour window
  cutoff            = 1                        # Stop 1 hour before end
  allow_unassociated_targets = false
}

# 5. SSM Maintenance Window Task (Patch Execution)
resource "aws_ssm_maintenance_window_target" "patching_target" {
  window_id        = aws_ssm_maintenance_window.weekly_patching.id
  resource_type    = "INSTANCE"
  targets {
    key    = "tag:PatchGroup" # Assumes instances tagged with PatchGroup
    values = ["Windows-Critical", "RHEL-Critical"]
  }
}

resource "aws_ssm_maintenance_window_task" "patching_task" {
  window_id        = aws_ssm_maintenance_window.weekly_patching.id
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  priority         = 10
  max_concurrency  = "10" # Adjust based on your fleet size
  max_errors       = "1"
  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.patching_target.id]
  }
  task_invocation_parameters {
    run_command_parameters {
      document_version = "$LATEST"
      parameter {
        name   = "Operation"
        values = ["Install"]
      }
      output_s3_bucket_name = "your-s3-bucket" # Optional: Replace with your bucket for logs
      output_s3_key_prefix  = "ssm-logs/"
    }
  }
}

# Output SNS Topic ARN for reference
output "sns_topic_arn" {
  value = aws_sns_topic.patch_failure_notifications.arn
}
```

### Prerequisites and Notes
1. **IAM Role for EC2 Instances**:
   - This code assumes your EC2 instances already have an IAM role with the `AmazonSSMManagedInstanceCore` policy. If not, add this Terraform block:
     ```hcl
     resource "aws_iam_role" "ssm_role" {
       name = "SSMManagedInstanceRole"
       assume_role_policy = jsonencode({
         Version = "2012-10-17"
         Statement = [{
           Action = "sts:AssumeRole"
           Effect = "Allow"
           Principal = { Service = "ec2.amazonaws.com" }
         }]
       })
     }

     resource "aws_iam_role_policy_attachment" "ssm_policy" {
       role       = aws_iam_role.ssm_role.name
       policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
     }

     resource "aws_iam_instance_profile" "ssm_profile" {
       name = "SSMManagedInstanceProfile"
       role = aws_iam_role.ssm_role.name
     }
     ```
   - Attach this profile to your EC2 instances.

2. **Tagging Instances**:
   - The Maintenance Window targets instances tagged with `PatchGroup:Windows-Critical` or `PatchGroup:RHEL-Critical`. Tag your instances accordingly, or modify the `targets` block to use instance IDs or another method.

3. **S3 Bucket for Logs** (Optional):
   - If you want SSM command output logged to S3, create an S3 bucket and update the `output_s3_bucket_name` in the `aws_ssm_maintenance_window_task` resource.

4. **Email Confirmation**:
   - After applying this Terraform config, AWS SNS will send a confirmation email to the `email_address`. Accept it to activate the subscription.

5. **Apply the Configuration**:
   - Run:
     ```bash
     terraform init
     terraform plan
     terraform apply
     ```
   - Review the plan and confirm with `yes`.

### How It Works with Terraform
- **SNS and CloudWatch**: Provisions the notification system to email you when an SSM patch command fails, including instance ID, command ID, and failure details.
- **Patch Baselines**: Defines critical-only patch policies for Windows (aligned with Patch Tuesday) and RHEL.
- **Maintenance Window**: Automates weekly patching every Wednesday at 2:00 AM UTC, targeting tagged instances.
- **Idempotency**: Terraform ensures resources are created or updated consistently, avoiding manual drift.

### Customization
- **Region/Timezone**: Adjust `provider "aws"` region and `schedule` in the Maintenance Window to match your timezone.
- **Patch Groups**: Modify the `targets` in `aws_ssm_maintenance_window_target` to fit your instance tagging strategy.
- **More Granular Failure Details**: Enhance the CloudWatch Event `input_template` or integrate with CloudWatch Logs as needed.

This Terraform setup fully automates your patching and notification requirements. Let me know if you’d like to tweak any part further!

### Outstanding
https://chat.deepseek.com/a/chat/s/6dc8da1f-9772-495a-b3f9-2b792086279d

### Resource
https://powershellcommands.com/powershell-running-in-background
