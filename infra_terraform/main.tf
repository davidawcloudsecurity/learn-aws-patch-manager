# ============================================================
# main.tf — Jenkins on Windows Server 2019
# Architecture: Route53 → CloudFront → ALB → Jenkins Controllers
#               Jenkins Agents in ASG (Windows Server 2019)
#               EFS shared storage, S3 artifacts
# ============================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ============================================================
# LOCALS
# ============================================================

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  azs = ["${var.aws_region}a", "${var.aws_region}b"]

  public_subnet_cidrs      = ["172.168.1.0/24", "172.168.2.0/24"]
  private_controller_cidrs = ["172.168.11.0/24", "172.168.12.0/24"]
  private_agent_cidrs      = ["172.168.21.0/24", "172.168.22.0/24"]

  tags = {
    Project       = var.project_name
    Environment   = var.environment
    ManagedBy     = "Terraform"
    "auto-delete" = "no"
  }
}

# ============================================================
# VPC & NETWORKING
# ============================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.tags, { Name = "${local.name_prefix}-igw" })
}

# Public Subnets (ALB)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-public-${count.index + 1}"
    Tier = "Public"
  })
}

# Private Subnets (Jenkins Controllers)
resource "aws_subnet" "private_controller" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_controller_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-private-controller-${count.index + 1}"
    Tier = "Private-Controller"
  })
}

# Private Subnets (Jenkins Agents - ASG)
resource "aws_subnet" "private_agent" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_agent_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = merge(local.tags, {
    Name = "${local.name_prefix}-private-agent-${count.index + 1}"
    Tier = "Private-Agent"
  })
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = 2
  domain = "vpc"

  tags       = merge(local.tags, { Name = "${local.name_prefix}-nat-eip-${count.index + 1}" })
  depends_on = [aws_internet_gateway.main]
}

# NAT Gateways (one per AZ for HA)
resource "aws_nat_gateway" "main" {
  count         = 2
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags       = merge(local.tags, { Name = "${local.name_prefix}-nat-${count.index + 1}" })
  depends_on = [aws_internet_gateway.main]
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-rt-public" })
}

resource "aws_route_table" "private_controller" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-rt-controller-${count.index + 1}" })
}

resource "aws_route_table" "private_agent" {
  count  = 2
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-rt-agent-${count.index + 1}" })
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_controller" {
  count          = 2
  subnet_id      = aws_subnet.private_controller[count.index].id
  route_table_id = aws_route_table.private_controller[count.index].id
}

resource "aws_route_table_association" "private_agent" {
  count          = 2
  subnet_id      = aws_subnet.private_agent[count.index].id
  route_table_id = aws_route_table.private_agent[count.index].id
}

# ============================================================
# SECURITY GROUPS
# ============================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-sg-alb"
  description = "ALB - HTTPS from CloudFront"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet (CloudFront)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-sg-alb" })
}

# Jenkins Controller Security Group
resource "aws_security_group" "jenkins_controller" {
  name        = "${local.name_prefix}-sg-controller"
  description = "Jenkins Controllers - traffic from ALB and agents"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Jenkins UI from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Jenkins JNLP from Agents"
    from_port       = 50000
    to_port         = 50000
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins_agent.id]
  }

  ingress {
    description = "WinRM from within VPC"
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "EFS NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-sg-controller" })
}

# Jenkins Agent Security Group
resource "aws_security_group" "jenkins_agent" {
  name        = "${local.name_prefix}-sg-agent"
  description = "Jenkins Agents (ASG) - WinRM access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "WinRM from within VPC"
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-sg-agent" })
}

# EFS Security Group
resource "aws_security_group" "efs" {
  name        = "${local.name_prefix}-sg-efs"
  description = "EFS - NFS from controllers and agents"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "NFS from Controllers"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins_controller.id]
  }

  ingress {
    description     = "NFS from Agents"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.jenkins_agent.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-sg-efs" })
}

# ============================================================
# IAM ROLES
# ============================================================

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# --- Controller Role ---
resource "aws_iam_role" "jenkins_controller" {
  count              = var.create_iam ? 1 : 0
  name               = "${local.name_prefix}-role-controller"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = local.tags
}

data "aws_iam_role" "jenkins_controller" {
  count = var.create_iam ? 0 : 1
  name  = "${local.name_prefix}-role-controller"
}

locals {
  controller_role_name = var.create_iam ? aws_iam_role.jenkins_controller[0].name : data.aws_iam_role.jenkins_controller[0].name
  agent_role_name      = var.create_iam ? aws_iam_role.jenkins_agent[0].name : data.aws_iam_role.jenkins_agent[0].name
}

resource "aws_iam_role_policy_attachment" "controller_ssm" {
  count      = var.create_iam ? 1 : 0
  role       = local.controller_role_name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "controller_cloudwatch" {
  count      = var.create_iam ? 1 : 0
  role       = local.controller_role_name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_policy" "jenkins_controller_policy" {
  count       = var.create_iam ? 1 : 0
  name        = "${local.name_prefix}-policy-controller"
  description = "Jenkins Controller custom permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = [
          local.s3_bucket_arn,
          "${local.s3_bucket_arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:SetDesiredCapacity",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "controller_custom" {
  count      = var.create_iam ? 1 : 0
  role       = local.controller_role_name
  policy_arn = aws_iam_policy.jenkins_controller_policy[0].arn
}

resource "aws_iam_instance_profile" "jenkins_controller" {
  count = var.create_iam ? 1 : 0
  name  = "${local.name_prefix}-profile-controller"
  role  = local.controller_role_name
}

data "aws_iam_instance_profile" "jenkins_controller" {
  count = var.create_iam ? 0 : 1
  name  = "${local.name_prefix}-profile-controller"
}

# --- Agent Role ---
resource "aws_iam_role" "jenkins_agent" {
  count              = var.create_iam ? 1 : 0
  name               = "${local.name_prefix}-role-agent"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = local.tags
}

data "aws_iam_role" "jenkins_agent" {
  count = var.create_iam ? 0 : 1
  name  = "${local.name_prefix}-role-agent"
}

resource "aws_iam_role_policy_attachment" "agent_ssm" {
  count      = var.create_iam ? 1 : 0
  role       = local.agent_role_name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "agent_cloudwatch" {
  count      = var.create_iam ? 1 : 0
  role       = local.agent_role_name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_policy" "jenkins_agent_policy" {
  count       = var.create_iam ? 1 : 0
  name        = "${local.name_prefix}-policy-agent"
  description = "Jenkins Agent custom permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          local.s3_bucket_arn,
          "${local.s3_bucket_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agent_custom" {
  count      = var.create_iam ? 1 : 0
  role       = local.agent_role_name
  policy_arn = aws_iam_policy.jenkins_agent_policy[0].arn
}

resource "aws_iam_instance_profile" "jenkins_agent" {
  count = var.create_iam ? 1 : 0
  name  = "${local.name_prefix}-profile-agent"
  role  = local.agent_role_name
}

data "aws_iam_instance_profile" "jenkins_agent" {
  count = var.create_iam ? 0 : 1
  name  = "${local.name_prefix}-profile-agent"
}

locals {
  controller_instance_profile = var.create_iam ? aws_iam_instance_profile.jenkins_controller[0].name : data.aws_iam_instance_profile.jenkins_controller[0].name
  agent_instance_profile      = var.create_iam ? aws_iam_instance_profile.jenkins_agent[0].name : data.aws_iam_instance_profile.jenkins_agent[0].name
}

# ============================================================
# S3 BUCKET — Artifacts, backups, logs
# ============================================================

resource "aws_s3_bucket" "jenkins_artifacts" {
  count  = var.create_s3 ? 1 : 0
  bucket = "${local.name_prefix}-artifacts-${data.aws_caller_identity.current.account_id}"
  tags   = merge(local.tags, { Name = "${local.name_prefix}-artifacts" })
}

data "aws_s3_bucket" "jenkins_artifacts" {
  count  = var.create_s3 ? 0 : 1
  bucket = "${local.name_prefix}-artifacts-${data.aws_caller_identity.current.account_id}"
}

locals {
  s3_bucket_arn = var.create_s3 ? aws_s3_bucket.jenkins_artifacts[0].arn : data.aws_s3_bucket.jenkins_artifacts[0].arn
  s3_bucket_id  = var.create_s3 ? aws_s3_bucket.jenkins_artifacts[0].id : data.aws_s3_bucket.jenkins_artifacts[0].id
}

resource "aws_s3_bucket_versioning" "jenkins_artifacts" {
  count  = var.create_s3 ? 1 : 0
  bucket = local.s3_bucket_id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "jenkins_artifacts" {
  count  = var.create_s3 ? 1 : 0
  bucket = local.s3_bucket_id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "jenkins_artifacts" {
  count                   = var.create_s3 ? 1 : 0
  bucket                  = local.s3_bucket_id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

# ============================================================
# EFS — Shared Jenkins Home
# ============================================================

resource "aws_efs_file_system" "jenkins" {
  count          = var.create_efs ? 1 : 0
  creation_token = "${local.name_prefix}-efs"
  encrypted      = true

  tags = merge(local.tags, { Name = "${local.name_prefix}-efs" })
}

data "aws_efs_file_system" "jenkins" {
  count          = var.create_efs ? 0 : 1
  creation_token = "${local.name_prefix}-efs"
}

locals {
  efs_id = var.create_efs ? aws_efs_file_system.jenkins[0].id : data.aws_efs_file_system.jenkins[0].file_system_id
}

# EFS mount targets in controller subnets — agents in same AZs can access them
resource "aws_efs_mount_target" "controller" {
  count           = var.create_efs ? 2 : 0
  file_system_id  = local.efs_id
  subnet_id       = aws_subnet.private_controller[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# ============================================================
# APPLICATION LOAD BALANCER
# ============================================================

resource "aws_lb" "jenkins" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = merge(local.tags, { Name = "${local.name_prefix}-alb" })
}

resource "aws_lb_target_group" "jenkins" {
  name     = "${local.name_prefix}-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/login"
    port                = "8080"
    protocol            = "HTTP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 10
    interval            = 30
    matcher             = "200,302"
  }

  tags = merge(local.tags, { Name = "${local.name_prefix}-tg" })
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.jenkins.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.jenkins.arn
  }
}

# ============================================================
# LAUNCH TEMPLATE + ASG — Jenkins Controller (Windows Server 2019)
# ============================================================

resource "aws_launch_template" "jenkins_controller" {
  name_prefix   = "${local.name_prefix}-controller-"
  image_id      = var.windows_ami_id
  instance_type = var.controller_instance_type

  iam_instance_profile { name = local.controller_instance_profile }

  vpc_security_group_ids = [aws_security_group.jenkins_controller.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.tags, {
      Name = "${local.name_prefix}-controller"
      Role = "JenkinsController"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, { Name = "${local.name_prefix}-controller-vol" })
  }

  user_data = base64encode(<<-EOF
    <powershell>
    # SSM Agent
    Start-Service AmazonSSMAgent
    Set-Service AmazonSSMAgent -StartupType Automatic

    # Install NFS client for EFS
    Install-WindowsFeature -Name NFS-Client

    # Mount EFS
    $EfsId = "${local.efs_id}"
    $EfsDns = "$EfsId.efs.${var.aws_region}.amazonaws.com"
    New-Item -ItemType Directory -Path "C:\efshare" -Force
    cmd /c "mount -o nolock $EfsDns:/ C:\efshare"

    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Install Java 17 and Jenkins
    choco install corretto17jdk -y
    choco install jenkins -y

    # Jenkins runs on port 8080 by default
    Start-Sleep -Seconds 30
    Set-Service Jenkins -StartupType Automatic
    Write-Output "Controller bootstrap complete. Jenkins on port 8080."
    </powershell>
  EOF
  )

  lifecycle { create_before_destroy = true }
  tags = merge(local.tags, { Name = "${local.name_prefix}-controller-lt" })
}

resource "aws_autoscaling_group" "jenkins_controllers" {
  name                      = "${local.name_prefix}-controllers-asg"
  desired_capacity          = 2
  min_size                  = 2
  max_size                  = 2
  vpc_zone_identifier       = aws_subnet.private_controller[*].id
  health_check_type         = "ELB"
  health_check_grace_period = 600
  wait_for_capacity_timeout = "15m"
  target_group_arns         = [aws_lb_target_group.jenkins.arn]

  launch_template {
    id      = aws_launch_template.jenkins_controller.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-controller"
    propagate_at_launch = true
  }
  tag {
    key                 = "Role"
    value               = "JenkinsController"
    propagate_at_launch = true
  }
  tag {
    key                 = "auto-delete"
    value               = "no"
    propagate_at_launch = true
  }

  depends_on = [aws_nat_gateway.main]
}

# ============================================================
# LAUNCH TEMPLATE — Jenkins Agent (Windows Server 2019 ASG)
# ============================================================

resource "aws_launch_template" "jenkins_agent" {
  name_prefix   = "${local.name_prefix}-agent-"
  image_id      = var.windows_ami_id
  instance_type = var.agent_instance_type

  iam_instance_profile { name = local.agent_instance_profile }

  vpc_security_group_ids = [aws_security_group.jenkins_agent.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.tags, {
      Name = "${local.name_prefix}-agent"
      Role = "JenkinsAgent"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(local.tags, { Name = "${local.name_prefix}-agent-vol" })
  }

  user_data = base64encode(<<-EOF
    <powershell>
    # SSM Agent
    Start-Service AmazonSSMAgent
    Set-Service AmazonSSMAgent -StartupType Automatic

    # Install NFS client for EFS
    Install-WindowsFeature -Name NFS-Client

    # Mount EFS
    $EfsId = "${local.efs_id}"
    $EfsDns = "$EfsId.efs.${var.aws_region}.amazonaws.com"
    New-Item -ItemType Directory -Path "C:\efshare" -Force
    cmd /c "mount -o nolock $EfsDns:/ C:\efshare"

    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    # Install Java 17 (required for Jenkins JNLP agent)
    choco install corretto17jdk -y

    Write-Output "Agent bootstrap complete. Java installed for JNLP connection."
    </powershell>
  EOF
  )

  lifecycle { create_before_destroy = true }
  tags = merge(local.tags, { Name = "${local.name_prefix}-agent-lt" })
}

# ============================================================
# AUTO SCALING GROUP — Jenkins Agents (no ALB attachment)
# ============================================================

resource "aws_autoscaling_group" "jenkins_agents" {
  name                      = "${local.name_prefix}-agents-asg"
  desired_capacity          = var.agent_desired_capacity
  min_size                  = var.agent_min_size
  max_size                  = var.agent_max_size
  vpc_zone_identifier       = aws_subnet.private_agent[*].id
  health_check_type         = "EC2"
  health_check_grace_period = 300
  wait_for_capacity_timeout = "15m"

  launch_template {
    id      = aws_launch_template.jenkins_agent.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences { min_healthy_percentage = 50 }
  }

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-agent"
    propagate_at_launch = true
  }
  tag {
    key                 = "Role"
    value               = "JenkinsAgent"
    propagate_at_launch = true
  }
  tag {
    key                 = "auto-delete"
    value               = "no"
    propagate_at_launch = true
  }

  depends_on = [aws_nat_gateway.main]
}

# ============================================================
# CLOUDFRONT DISTRIBUTION
# ============================================================

resource "aws_cloudfront_distribution" "jenkins" {
  enabled             = true
  default_root_object = ""
  price_class         = "PriceClass_200"
  comment             = "Jenkins UI - ${local.name_prefix}"

  tags = merge(local.tags, { Name = "${local.name_prefix}-cloudfront" })

  origin {
    domain_name = aws_lb.jenkins.dns_name
    origin_id   = "alb-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "alb-origin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = true
      headers      = ["Host", "Origin", "Authorization"]
      cookies { forward = "all" }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }
}

# ============================================================
# OUTPUTS
# ============================================================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.jenkins.dns_name
}

output "cloudfront_domain" {
  description = "CloudFront distribution domain"
  value       = aws_cloudfront_distribution.jenkins.domain_name
}

output "jenkins_url" {
  description = "Jenkins URL via CloudFront"
  value       = "https://${aws_cloudfront_distribution.jenkins.domain_name}"
}

output "efs_id" {
  description = "EFS file system ID"
  value       = local.efs_id
}

output "asg_name" {
  description = "Jenkins Agents ASG name"
  value       = aws_autoscaling_group.jenkins_agents.name
}

output "s3_bucket" {
  description = "Jenkins artifacts S3 bucket"
  value       = local.s3_bucket_id
}
