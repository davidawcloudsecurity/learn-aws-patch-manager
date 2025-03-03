**Step 1: Ensure EC2 Instances Have SSM Connectivity**  
Start by verifying/adding the **IAM role** with the `AmazonSSMManagedInstanceCore` policy to your existing EC2 instances. SSM requires this to manage patches/configurations.  

### Terraform Snippet (IAM Role):  
```hcl
resource "aws_iam_role" "ssm_ec2_role" {
  name = "SSM-EC2-Managed-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
```  

**Next Step**: Attach this role to your existing EC2 instances (manually via AWS Console/CLI or via Terraform if managed).  

Let me know when you're ready for **Step 2** (SSM Patch Management setup). Keep it minimal?

**Step 2: Configure SSM Patch Management**  
Set up **Patch Baselines** and **Maintenance Windows** to automate patching for Windows and RHEL instances.  

### Terraform Snippet (Patch Baseline + Maintenance Window):  
```hcl
# Define a maintenance window for patching
resource "aws_ssm_maintenance_window" "patch_window" {
  name         = "Monthly-Patch-Window"
  schedule     = "cron(0 0 18 ? * SAT *)"  # Example: 6pm UTC every Saturday
  duration     = 3   # Hours
  cutoff       = 1   # Stop new tasks 1 hour before end
}

# Define patch baseline for Windows
resource "aws_ssm_patch_baseline" "windows_baseline" {
  name             = "Windows-Critical-Updates"
  operating_system = "WINDOWS"
  approval_rule {
    approve_after_days = 0
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["CriticalUpdates", "SecurityUpdates"]
    }
  }
}

# Define patch baseline for RHEL
resource "aws_ssm_patch_baseline" "rhel_baseline" {
  name             = "RHEL-Security-Updates"
  operating_system = "REDHAT_ENTERPRISE_LINUX"
  approval_rule {
    approve_after_days = 0
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }
  }
}

# Assign instances to patch groups (via tags)
# Tag your existing EC2 instances with:
# - Key: "PatchGroup"
# - Value: "Windows-Prod" or "RHEL-Prod" (match the baseline)
```

**Next Action**:  
1. **Tag your existing EC2 instances** with `PatchGroup` to associate them with baselines.  
2. Use AWS Default patching templates or customize further (e.g., reboot settings, patch exceptions).  

Proceed to **Step 3** (Automate patch deployment via SSM Associations)?  
*(Still keeping it concise?)*

**Step 3: Automate Patch Deployment with SSM Associations**  
Create **SSM Associations** to trigger patch installations during maintenance windows.  

### Terraform Snippet (SSM Association):  
```hcl
# For Windows instances
resource "aws_ssm_association" "windows_patch" {
  name = "AWS-RunPatchBaseline"  # AWS predefined document

  targets {
    key    = "tag:PatchGroup"
    values = ["Windows-Prod"]  # Matches EC2 instance tag from Step 2
  }

  parameters = {
    Operation                        = "Install"
    RebootOption                     = "RebootIfNeeded"  # Or "NoReboot"
    BaselineOverride                 = aws_ssm_patch_baseline.windows_baseline.arn
  }

  schedule_expression = aws_ssm_maintenance_window.patch_window.schedule
}

# For RHEL instances
resource "aws_ssm_association" "rhel_patch" {
  name = "AWS-RunPatchBaseline"

  targets {
    key    = "tag:PatchGroup"
    values = ["RHEL-Prod"]
  }

  parameters = {
    Operation        = "Install"
    RebootOption     = "RebootIfNeeded"  # Recommended for Linux
    BaselineOverride = aws_ssm_patch_baseline.rhel_baseline.arn
  }

  schedule_expression = aws_ssm_maintenance_window.patch_window.schedule
}
```

**Key Actions After Deployment**:  
1. **Monitor compliance** via AWS SSM → **Patch Manager**.  
2. Adjust parameters (e.g., `RebootOption`) based on your environment’s tolerance.  

**Next Optional Step**:  
Set up **SSM State Manager** for ongoing configuration compliance (e.g., enforcing specific OS settings).  

Need this, or done for now?
