# -------------------------------------------------------
# IAM Role for Systems Manager Maintenance Window
# -------------------------------------------------------
# This role is assumed by AWS Systems Manager to execute
# patch baselines and run PowerShell commands during
# maintenance windows.

resource "aws_iam_role" "maintenance_window_role" {
  name_prefix = "${var.project_tag}-mw-"
  description = "Role for Systems Manager Maintenance Window to run patch baselines and PowerShell"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_tag}-maintenance-window-role"
  }
}

# -------------------------------------------------------
# Policy for Patch Manager Operations
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_patch_policy" {
  name_prefix = "${var.project_tag}-mw-patch-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPatchBaselineOperations"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation",
          "ssm:ListAssociations",
          "ssm:GetAutomationExecution",
          "ssm:StartAutomationExecution",
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowPatchGroupOperations"
        Effect = "Allow"
        Action = [
          "patch:DescribePatches",
          "patch:GetPatchBaseline",
          "patch:DescribePatchBaselines",
          "patch:DescribePatchGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowEC2Operations"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags",
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::aws-ssm-${data.aws_caller_identity.current.account_id}-*/*"
      }
    ]
  })
}

# -------------------------------------------------------
# Policy for PowerShell Command Execution
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_powershell_policy" {
  name_prefix = "${var.project_tag}-mw-ps-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPowerShellExecution"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:document/AWS-RunPowerShellScript",
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:document/AWS-RunShellScript",
          "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
      },
      {
        Sid    = "AllowRunPatchBaseline"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-RunPatchBaseline",
          "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
      },
      {
        Sid    = "AllowPassRoleToEC2"
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.ssm_role.arn
        ]
      }
    ]
  })
}

# -------------------------------------------------------
# CloudWatch Logs Policy for Maintenance Window
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_logs_policy" {
  name_prefix = "${var.project_tag}-mw-logs-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLogsOperations"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ssm/${var.project_tag}*"
      }
    ]
  })
}

# -------------------------------------------------------
# Data Sources for Account & Region Info
# -------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -------------------------------------------------------
# Output the Maintenance Window Role ARN
# -------------------------------------------------------
output "maintenance_window_role_arn" {
  description = "ARN of the Maintenance Window IAM role"
  value       = aws_iam_role.maintenance_window_role.arn
}

output "maintenance_window_role_name" {
  description = "Name of the Maintenance Window IAM role"
  value       = aws_iam_role.maintenance_window_role.name
}
