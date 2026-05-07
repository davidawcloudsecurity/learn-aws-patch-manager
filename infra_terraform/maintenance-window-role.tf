# -------------------------------------------------------
# Data Sources for Account & Region Info
# -------------------------------------------------------
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# -------------------------------------------------------
# IAM Role for Systems Manager Maintenance Window
# -------------------------------------------------------
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
# Attach the CORRECT Managed Policy for Maintenance Window Service Role
# -------------------------------------------------------
resource "aws_iam_role_policy_attachment" "maintenance_window_ssm_mw_role" {
  role       = aws_iam_role.maintenance_window_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSSMMaintenanceWindowRole"
}

# -------------------------------------------------------
# Additional inline policy for Patch Manager & PowerShell
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_patch_policy" {
  name_prefix = "${var.project_tag}-mw-patch-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSMCoreOperations"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation",
          "ssm:ListAssociations",
          "ssm:GetAutomationExecution",
          "ssm:StartAutomationExecution",
          "ssm:GetCommandInvocation",
          "ssm:ListCommandInvocations",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:DescribePatchGroupState",
          "ssm:DescribePatchBaselines",
          "ssm:DescribePatchGroups",
          "ssm:GetPatchBaseline",
          "ssm:DescribeInstancePatchStates",
          "ssm:DescribeInstancePatches"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowSendCommandRunPatchBaseline"
        Effect = "Allow"
        Action = ["ssm:SendCommand"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-RunPatchBaseline",
          "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
      },
      {
        Sid    = "AllowSendCommandPowerShell"
        Effect = "Allow"
        Action = ["ssm:SendCommand"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-RunPowerShellScript",
          "arn:aws:ssm:${data.aws_region.current.name}::document/AWS-RunShellScript",
          "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/*"
        ]
      },
      {
        Sid    = "AllowEC2Describe"
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
      },
      {
        Sid    = "AllowPassRoleToEC2"
        Effect = "Allow"
        Action = ["iam:PassRole"]
        Resource = [aws_iam_role.ssm_role.arn]
      }
    ]
  })
}

# -------------------------------------------------------
# Policy for EC2 Messages Service
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_ec2messages_policy" {
  name_prefix = "${var.project_tag}-mw-ec2msg-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEC2MessagesService"
        Effect = "Allow"
        Action = [
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages"
        ]
        Resource = "*"
      }
    ]
  })
}

# -------------------------------------------------------
# Policy for SSM Messages Service
# -------------------------------------------------------
resource "aws_iam_role_policy" "maintenance_window_ssmmessages_policy" {
  name_prefix = "${var.project_tag}-mw-ssmmsg-"
  role        = aws_iam_role.maintenance_window_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSSMMessagesService"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
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
# Outputs
# -------------------------------------------------------
output "maintenance_window_role_arn" {
  description = "ARN of the Maintenance Window IAM role"
  value       = aws_iam_role.maintenance_window_role.arn
}

output "maintenance_window_role_name" {
  description = "Name of the Maintenance Window IAM role"
  value       = aws_iam_role.maintenance_window_role.name
}
