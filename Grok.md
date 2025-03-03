Below is a comprehensive response to your query about setting up automated patch and configuration management for existing Windows and RHEL EC2 instances in an air-gapped environment using Terraform, along with managing resource health and automating deployments with AWS Systems Manager (SSM). I’ll also address how you’ll know which updates to download, how notifications work, and how to handle updates for both Windows and RHEL.

---

## Overview

You want to use Terraform to configure automated patch and configuration management for existing production Windows and RHEL EC2 instances running in an air-gapped environment. Additionally, you’re leveraging SSM to manage resource health, automate deployments, and perform maintenance tasks. Since the environment is air-gapped, internet access is restricted, requiring a tailored approach for update management. After receiving notifications, you’ll manually download the required updates (KB/CAB files for Windows, RPM/tar.gz/repo files for RHEL) and upload them to an S3 bucket with a date-based prefix.

Here’s how we’ll achieve this:

1. **Terraform Configuration**: Set up the necessary AWS resources (IAM roles, S3 bucket, SSM patch baselines, maintenance windows) to support existing EC2 instances.
2. **SSM Integration**: Use SSM to manage patching, configuration, and resource health.
3. **Air-Gapped Update Process**: Handle updates manually due to the lack of internet access.
4. **Notifications**: Configure notifications via SNS (adapted for air-gapped constraints).
5. **Update Determination**: Explain how to identify required updates since Terraform doesn’t provide this information directly.

---

## Terraform Script

Since your EC2 instances already exist, the Terraform script will focus on attaching the necessary configurations rather than provisioning new instances. Below is the script:

```terraform
provider "aws" {
  region = "us-west-2"  # Update to your preferred region
}

# IAM Role for existing EC2 instances to use SSM and access S3
resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2_ssm_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Attach SSM managed policy
resource "aws_iam_role_policy_attachment" "ec2_ssm_policy" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Attach S3 read access policy for update files
resource "aws_iam_role_policy" "s3_access_policy" {
  role = aws_iam_role.ec2_ssm_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.updates_bucket.arn,
          "${aws_s3_bucket.updates_bucket.arn}/*"
        ]
      }
    ]
  })
}

# EC2 Instance Profile
resource "aws_iam_instance_profile" "ec2_ssm_profile" {
  name = "ec2_ssm_profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# Note: Attach this instance profile to your existing EC2 instances manually or via AWS CLI:
# aws ec2 associate-iam-instance-profile --instance-id <instance-id> --iam-instance-profile Name=ec2_ssm_profile

# S3 Bucket for storing update files
resource "aws_s3_bucket" "updates_bucket" {
  bucket = "my-updates-bucket"  # Choose a unique bucket name
  acl    = "private"
}

# SSM Patch Baseline for Windows
resource "aws_ssm_patch_baseline" "windows_baseline" {
  name             = "windows-baseline"
  operating_system = "WINDOWS"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "CriticalUpdates"]
    }
  }
}

# SSM Patch Baseline for RHEL
resource "aws_ssm_patch_baseline" "rhel_baseline" {
  name             = "rhel-baseline"
  operating_system = "REDHAT_ENTERPRISE_LINUX"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"
    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }
}

# Maintenance Window
resource "aws_ssm_maintenance_window" "maintenance_window" {
  name     = "maintenance-window"
  schedule = "cron(0 2 ? * SUN *)"  # Every Sunday at 2 AM
  duration = 3  # Duration in hours
  cutoff   = 1  # Cutoff time in hours before end of window
}

# SNS Topic for Notifications
resource "aws_sns_topic" "patch_notifications" {
  name = "patch-notifications"
}

# Note: Subscribe to this topic manually (e.g., via email or internal endpoint) in your air-gapped environment
```

### Applying the Script

1. **Run Terraform**:
   - Save the script as `main.tf`.
   - Run `terraform init`, then `terraform apply`.

2. **Attach IAM Instance Profile**:
   - Since the EC2 instances already exist, manually attach the `ec2_ssm_profile` to each instance using the AWS CLI:
     ```bash
     aws ec2 associate-iam-instance-profile --instance-id <windows-instance-id> --iam-instance-profile Name=ec2_ssm_profile
     aws ec2 associate-iam-instance-profile --instance-id <rhel-instance-id> --iam-instance-profile Name=ec2_ssm_profile
     ```
   - Ensure the SSM Agent is installed and running on both instances.

---

## Configuring SSM for Patch and Configuration Management

### Patch Management

- **Patch Baselines**: The script defines patch baselines for Windows (security and critical updates) and RHEL (critical and important updates).
- **Maintenance Window**: Patches are applied during the scheduled maintenance window (e.g., every Sunday at 2 AM).

### Resource Health

- Use SSM Inventory to monitor the health of your instances:
  - Configure an SSM Association to collect inventory data:
    ```bash
    aws ssm create-association --name AWS-GatherSoftwareInventory --targets Key=InstanceIds,Values=<windows-instance-id>,<rhel-instance-id>
    ```
  - View inventory in the AWS Management Console under Systems Manager > Inventory.

### Automated Deployments and Maintenance

- Create SSM Automation Documents to deploy updates or perform maintenance tasks.
- Example for Windows (install updates from S3):
  ```yaml
  schemaVersion: '0.3'
  description: 'Install Windows Updates from S3'
  parameters:
    S3Bucket:
      type: String
      default: 'my-updates-bucket'
    S3Prefix:
      type: String
      default: 'updates/{{CURRENT_DATE}}'  # Replace with actual date, e.g., updates/2023-10-05
  mainSteps:
    - name: DownloadUpdates
      action: aws:executeScript
      inputs:
        Runtime: PowerShell
        Script: |
          $bucket = '{{ S3Bucket }}'
          $prefix = '{{ S3Prefix }}'
          $localPath = 'C:\updates'
          New-Item -ItemType Directory -Path $localPath -Force
          $objects = aws s3 ls "s3://$bucket/$prefix/" | ForEach-Object { $_.Split()[-1] }
          foreach ($obj in $objects) {
            aws s3 cp "s3://$bucket/$prefix/$obj" "$localPath\$obj"
          }
    - name: InstallUpdates
      action: aws:executeScript
      inputs:
        Runtime: PowerShell
        Script: |
          $updateFiles = Get-ChildItem -Path 'C:\updates' -Filter *.msu
          foreach ($file in $updateFiles) {
            wusa.exe $file.FullName /quiet /norestart
          }
  ```
- Example for RHEL:
  ```yaml
  schemaVersion: '0.3'
  description: 'Install RHEL Updates from S3'
  parameters:
    S3Bucket:
      type: String
      default: 'my-updates-bucket'
    S3Prefix:
      type: String
      default: 'updates/{{CURRENT_DATE}}'  # Replace with actual date
  mainSteps:
    - name: DownloadUpdates
      action: aws:executeScript
      inputs:
        Runtime: bash
        Script: |
          bucket={{ S3Bucket }}
          prefix={{ S3Prefix }}
          mkdir -p /tmp/updates
          aws s3 cp "s3://$bucket/$prefix/" /tmp/updates --recursive
    - name: InstallUpdates
      action: aws:executeScript
      inputs:
        Runtime: bash
        Script: |
          rpm -Uvh /tmp/updates/*.rpm
  ```
- Apply these documents during the maintenance window using SSM Automation.

---

## Air-Gapped Environment Considerations

Since your environment is air-gapped:

- **VPC Endpoints**: Ensure SSM, S3, and SNS are accessible via VPC endpoints to avoid internet dependency.
  - Example: Create an S3 VPC endpoint:
    ```terraform
    resource "aws_vpc_endpoint" "s3" {
      vpc_id       = "<your-vpc-id>"
      service_name = "com.amazonaws.us-west-2.s3"
    }
    ```
- **Manual Update Handling**: You’ll need to manually fetch updates and upload them to the S3 bucket.

---

## How to Know What KB or CAB (Windows) and RPM or tar.gz (RHEL) to Download

### For Windows

- **Determining Updates**:
  - Terraform and SSM don’t automatically tell you which specific KB or CAB files are needed in an air-gapped environment.
  - Use SSM Inventory to check installed patches:
    ```bash
    aws ssm list-inventory-entries --instance-id <windows-instance-id> --type-name AWS:WindowsUpdate
    ```
  - Compare this with your organization’s security requirements or a list of desired updates (e.g., from Microsoft Update Catalog).
  - Alternatively, manually run `systeminfo` or a tool like WSUS Offline Update on a test system to identify missing updates.

- **Notification**:
  - Terraform itself doesn’t share this information via SES or SNS—it’s an infrastructure provisioning tool.
  - SSM can trigger SNS notifications when instances are non-compliant with the patch baseline:
    ```bash
    aws ssm create-association --name AWS-RunPatchBaseline --targets Key=InstanceIds,Values=<windows-instance-id> --parameters '{"BaselineId": ["<windows-baseline-id>"]}' --notification-config '{"NotificationArn": "<sns-topic-arn>", "NotificationEvents": ["All"], "NotificationType": "Command"}'
    ```
  - The notification will indicate compliance status but not specific KB/CAB files. You’ll need to determine these manually.

### For RHEL

- **Determining Updates**:
  - Use SSM Inventory to check installed packages:
    ```bash
    aws ssm list-inventory-entries --instance-id <rhel-instance-id> --type-name AWS:Application
    ```
  - Compare with a desired package list or run `yum check-update` on a test system with access to a RHEL repository mirror to identify missing RPMs.
  - If using a local repository, sync it manually and list required updates.

- **Notification**:
  - Similar to Windows, SSM can notify via SNS when the RHEL instance is non-compliant with the `rhel_baseline`. The process is the same as above, but specific RPMs or tar.gz files must be determined manually.

---

## After Receiving the Notification

1. **Download Updates**:
   - For Windows: Download the required KB or CAB files from the Microsoft Update Catalog based on your findings.
   - For RHEL: Download the required RPMs or tar.gz files from a RHEL subscription or mirror them locally.

2. **Upload to S3**:
   - Use the AWS CLI to upload files with a date-based prefix:
     ```bash
     CURRENT_DATE=$(date +%Y-%m-%d)
     aws s3 cp <path-to-windows-kb-files> s3://my-updates-bucket/updates/$CURRENT_DATE/ --recursive
     aws s3 cp <path-to-rhel-rpms> s3://my-updates-bucket/updates/$CURRENT_DATE/ --recursive
     ```

3. **Apply Updates**:
   - Execute the SSM Automation Documents during the maintenance window, specifying the `S3Prefix` as `updates/$CURRENT_DATE`.

---

## Summary

- **Terraform**: Configures IAM roles, S3 bucket, patch baselines, and maintenance windows for existing EC2 instances.
- **SSM**: Manages patching, resource health (via Inventory), and automation (via Documents).
- **Air-Gapped**: Manually determine and upload updates to S3; use VPC endpoints for AWS services.
- **Notifications**: SNS notifies you of compliance status, but you’ll manually identify specific updates.
- **Process**: After notification, download updates, upload to S3 with a date prefix, and apply via SSM.

This setup ensures your Windows and RHEL servers are maintained and patched in an air-gapped environment efficiently. Let me know if you need further clarification!
