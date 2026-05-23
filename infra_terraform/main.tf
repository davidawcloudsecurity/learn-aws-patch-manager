provider "aws" {
  region = var.region
}

# ============================================================
# VPC + Networking (2 AZs required for Managed AD)
# ============================================================

resource "aws_vpc" "main" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.main_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = var.project_tag }
}

locals {
  vpc_id = var.create_vpc ? aws_vpc.main[0].id : data.aws_vpc.existing[0].id
  ami_id = var.custom_ami_id != "" ? var.custom_ami_id : data.aws_ami.windows_2019[0].id
}

data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  filter {
    name   = "tag:Name"
    values = [var.project_tag]
  }
}

resource "aws_internet_gateway" "igw" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = local.vpc_id
  tags   = { Name = "${var.project_tag}-igw" }
}

resource "aws_subnet" "public" {
  count                   = var.create_vpc ? length(var.public_subnet_cidrs) : 0
  vpc_id                  = local.vpc_id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = { Name = "${var.project_tag}-public-${var.azs[count.index]}" }
}

resource "aws_subnet" "private" {
  count             = var.create_vpc ? length(var.private_subnet_cidrs) : 0
  vpc_id            = local.vpc_id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = { Name = "${var.project_tag}-private-${var.azs[count.index]}" }
}

# NAT Gateway — ASG instances in private subnets need outbound for patching
resource "aws_eip" "nat" {
  count  = var.create_vpc ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.project_tag}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  count         = var.create_vpc ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${var.project_tag}-nat-gw" }
  depends_on    = [aws_internet_gateway.igw]
}

resource "aws_route_table" "public" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = local.vpc_id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw[0].id
  }
  tags = { Name = "${var.project_tag}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = var.create_vpc ? length(aws_subnet.public) : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = local.vpc_id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[0].id
  }
  tags = { Name = "${var.project_tag}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = var.create_vpc ? length(aws_subnet.private) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# ============================================================
# AWS Managed Microsoft AD
# ============================================================

resource "aws_directory_service_directory" "managed_ad" {
  name     = var.ad_domain_name
  password = var.ad_admin_password
  edition  = var.ad_edition
  type     = "MicrosoftAD"

  vpc_settings {
    vpc_id     = local.vpc_id
    subnet_ids = aws_subnet.private[*].id
  }

  tags = { Name = "${var.project_tag}-managed-ad" }
}

# Point VPC DNS to Managed AD domain controllers
resource "aws_vpc_dhcp_options" "ad_dns" {
  domain_name         = var.ad_domain_name
  domain_name_servers = aws_directory_service_directory.managed_ad.dns_ip_addresses
  tags                = { Name = "${var.project_tag}-ad-dhcp" }
}

resource "aws_vpc_dhcp_options_association" "ad_dns" {
  vpc_id          = local.vpc_id
  dhcp_options_id = aws_vpc_dhcp_options.ad_dns.id
}

# ============================================================
# IAM Role — EC2 instances need SSM + Directory Service access
# ============================================================

resource "aws_iam_role" "ec2_ssm_ad" {
  name = "${var.project_tag}-ec2-ssm-ad-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.project_tag}-ec2-ssm-ad-role" }
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm_ad.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ssm_directory" {
  role       = aws_iam_role.ec2_ssm_ad.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMDirectoryServiceAccess"
}

resource "aws_iam_instance_profile" "ec2_ssm_ad" {
  name = "${var.project_tag}-ec2-ssm-ad-profile"
  role = aws_iam_role.ec2_ssm_ad.name
}

# ============================================================
# SSM Document + Association — Auto AD Domain Join
# ============================================================

resource "aws_ssm_document" "ad_join" {
  name          = "${var.project_tag}-ad-domain-join"
  document_type = "Command"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Join Windows instance to AWS Managed AD"
    mainSteps = [{
      action = "aws:domainJoin"
      name   = "domainJoin"
      inputs = {
        directoryId    = aws_directory_service_directory.managed_ad.id
        directoryName  = var.ad_domain_name
        dnsIpAddresses = aws_directory_service_directory.managed_ad.dns_ip_addresses
      }
    }]
  })

  tags = { Name = "${var.project_tag}-ad-join-doc" }
}

# Any instance tagged ADJoin=true will auto-join the domain
resource "aws_ssm_association" "ad_join" {
  name = aws_ssm_document.ad_join.name

  targets {
    key    = "tag:ADJoin"
    values = ["true"]
  }

  depends_on = [aws_directory_service_directory.managed_ad]
}

# ============================================================
# Security Group — Windows ASG (AD + SSM + Patching)
# ============================================================

resource "aws_security_group" "windows_asg" {
  name        = "${var.project_tag}-windows-asg-sg"
  description = "Windows ASG instances: AD-joined, SSM patching"
  vpc_id      = local.vpc_id

  # RDP from within VPC only
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "RDP from VPC"
  }

  # WinRM for SSM
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "WinRM"
  }

  # AD protocols (DNS, Kerberos, LDAP, SMB, LDAPS)
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "DNS TCP"
  }
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.main_cidr_block]
    description = "DNS UDP"
  }
  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "Kerberos"
  }
  ingress {
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "LDAP"
  }
  ingress {
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "SMB"
  }
  ingress {
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
    description = "LDAPS"
  }

  # All outbound (patching + SSM endpoints)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_tag}-windows-asg-sg" }
}

# ============================================================
# Windows Server 2019 AMI (latest)
# ============================================================

data "aws_ami" "windows_2019" {
  count       = var.custom_ami_id == "" ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================
# Launch Template
# ============================================================

resource "aws_launch_template" "windows" {
  name_prefix   = "${var.project_tag}-win-"
  image_id      = data.aws_ami.windows_2019.id
  instance_type = var.windows_instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_ssm_ad.name
  }

  vpc_security_group_ids = [aws_security_group.windows_asg.id]

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name       = "${var.project_tag}-win-asg"
      ADJoin     = "true"
      PatchGroup = "Windows-Production"
      OS         = "Windows Server 2019"
    }
  }

  tag_specifications {
    resource_type = "volume"
    tags = { Name = "${var.project_tag}-win-vol" }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = base64encode(<<-EOF
    <powershell>
    Start-Service AmazonSSMAgent
    Set-Service AmazonSSMAgent -StartupType Automatic
    Write-Output "Bootstrap complete. AD join handled by SSM Association."
    </powershell>
  EOF
  )

  lifecycle { create_before_destroy = true }

  tags = { Name = "${var.project_tag}-win-launch-template" }
}

# ============================================================
# Auto Scaling Group
# ============================================================

resource "aws_autoscaling_group" "windows" {
  name                      = "${var.project_tag}-windows-asg"
  desired_capacity          = var.asg_desired_capacity
  min_size                  = var.asg_min_size
  max_size                  = var.asg_max_size
  vpc_zone_identifier       = aws_subnet.private[*].id
  health_check_type         = "EC2"
  wait_for_capacity_timeout = "15m"

  launch_template {
    id      = aws_launch_template.windows.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_tag}-win-asg"
    propagate_at_launch = true
  }
  tag {
    key                 = "PatchGroup"
    value               = "Windows-Production"
    propagate_at_launch = true
  }
  tag {
    key                 = "ADJoin"
    value               = "true"
    propagate_at_launch = true
  }

  depends_on = [
    aws_directory_service_directory.managed_ad,
    aws_ssm_association.ad_join,
    aws_nat_gateway.nat
  ]
}

# ============================================================
# SSM Patch Baseline (Windows)
# ============================================================

resource "aws_ssm_patch_baseline" "windows" {
  name             = "${var.project_tag}-windows-baseline"
  operating_system = "WINDOWS"

  approval_rule {
    approve_after_days = 7
    compliance_level   = "CRITICAL"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["CriticalUpdates", "SecurityUpdates"]
    }
    patch_filter {
      key    = "MSRC_SEVERITY"
      values = ["Critical", "Important"]
    }
  }

  approval_rule {
    approve_after_days = 14
    compliance_level   = "HIGH"

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["UpdateRollups", "Updates"]
    }
  }

  tags = { Name = "${var.project_tag}-windows-patch-baseline" }
}

resource "aws_ssm_patch_group" "windows" {
  baseline_id = aws_ssm_patch_baseline.windows.id
  patch_group = "Windows-Production"
}

# ============================================================
# SSM Maintenance Window + Task
# ============================================================

resource "aws_ssm_maintenance_window" "patch" {
  name                       = "${var.project_tag}-patch-window"
  schedule                   = var.patch_schedule
  duration                   = var.patch_window_duration
  cutoff                     = var.patch_window_cutoff
  allow_unassociated_targets = false
  tags                       = { Name = "${var.project_tag}-patch-window" }
}

resource "aws_ssm_maintenance_window_target" "patch" {
  window_id     = aws_ssm_maintenance_window.patch.id
  name          = "${var.project_tag}-patch-targets"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:PatchGroup"
    values = ["Windows-Production"]
  }
}

resource "aws_ssm_maintenance_window_task" "patch" {
  window_id       = aws_ssm_maintenance_window.patch.id
  name            = "${var.project_tag}-run-patch-baseline"
  task_type       = "RUN_COMMAND"
  task_arn        = "AWS-RunPatchBaseline"
  priority        = 1
  max_concurrency = "50%"
  max_errors      = "25%"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.patch.id]
  }

  task_invocation_parameters {
    run_command_parameters {
      timeout_seconds = 3600

      parameter {
        name   = "Operation"
        values = ["Install"]
      }
      parameter {
        name   = "RebootOption"
        values = ["RebootIfNeeded"]
      }
    }
  }
}

# ============================================================
# Outputs
# ============================================================

output "vpc_id" {
  description = "VPC ID"
  value       = local.vpc_id
}

output "managed_ad_id" {
  description = "Managed AD directory ID"
  value       = aws_directory_service_directory.managed_ad.id
}

output "managed_ad_dns_ips" {
  description = "Managed AD DNS IPs"
  value       = aws_directory_service_directory.managed_ad.dns_ip_addresses
}

output "asg_name" {
  description = "Windows ASG name"
  value       = aws_autoscaling_group.windows.name
}

output "patch_baseline_id" {
  description = "SSM Patch Baseline ID"
  value       = aws_ssm_patch_baseline.windows.id
}

output "maintenance_window_id" {
  description = "SSM Maintenance Window ID"
  value       = aws_ssm_maintenance_window.patch.id
}

output "ami_id" {
  description = "AMI ID used by the launch template"
  value       = local.ami_id
}
