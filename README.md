# learn-aws-patch-manager
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
How to pull more information especailly for cumulative updates for .net
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
