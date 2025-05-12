# learn-aws-patch-manager
```
wget -O custom_name.zip http://example.com/file.zip
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
