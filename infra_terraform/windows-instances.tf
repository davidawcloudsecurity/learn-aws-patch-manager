

# Data source for Windows Server AMIs
data "aws_ami" "windows_2019" {
  count       = var.create_windows_instances ? 1 : 0
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
  }
}



# IAM role for Systems Manager
resource "aws_iam_role" "ssm_role" {
  name  = "${var.project_tag}-ssm-role"
  
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

resource "aws_iam_role_policy_attachment" "ssm_managed_instance_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
  name  = "${var.project_tag}-ssm-profile"
  role  = aws_iam_role.ssm_role.name
}

# Use IAM profile
locals {
  ssm_instance_profile = aws_iam_instance_profile.ssm_profile.name
}

# Security Group for Windows instances (in VPC-2)
resource "aws_security_group" "windows_sg" {
  count       = var.create_windows_instances ? 1 : 0
  name        = "windows-instances-sg"
  description = "Security group for Windows EC2 instances"
  vpc_id      = aws_vpc.windows_vpc[0].id
   
  ingress {
    from_port   = 8530
    to_port     = 8531
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    self            = true
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.project_tag}-windows-sg"
  }
}

# Windows Server 2019 - WSUS Server
resource "aws_instance" "wsus_server_2019" {
  count                      = var.create_windows_instances ? 1 : 0
  ami                        = "ami-0ca7038e6ff499fc0" # Windows_Server-2019-English-Full-Base-2026.03.11  |  2026-03-11T19:53:49.000Z
  instance_type              = "t3.medium"
  subnet_id                  = aws_subnet.windows_public_subnet[0].id
  vpc_security_group_ids     = [aws_security_group.windows_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = local.ssm_instance_profile
  
  user_data = <<-EOF
    <script>
    net user ec2-user P@ssw0rd123! /add /fullname:"EC2 User" /comment:"Local admin user"
    net localgroup administrators ec2-user /add
    mkdir C:\WSUS\WsusContent
    cd C:\WSUS\WsusContent
    curl -LO https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/11/windows10.0-kb5068791-x64_a8b1b1b6c7b6b673c5a5f32772749eb2bb80c88b.msu
    </script>
    <powershell>    
    # Install WSUS role with content directory specification
    Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
    
    # Create WSUS content directory
    New-Item -Path "C:\WSUS\WsusContent" -ItemType Directory -Force
    
    # Run post-installation configuration with the content path
    # This is the critical step that was missing
    & "C:\Program Files\Update Services\Tools\wsusutil.exe" postinstall CONTENT_DIR=C:\WSUS\WsusContent
    
    # Wait for post-installation to complete
    Start-Sleep -Seconds 30
    
    # Now configure WSUS
    Import-Module UpdateServices
    
    # Get WSUS server instance
    $wsusServer = Get-WsusServer
    
    # Start WSUS services
    Start-Service WsusService
    Set-Service WsusService -StartupType Automatic
    
    # Configure Windows Firewall
    New-NetFirewallRule -DisplayName "WSUS HTTP" -Direction Inbound -Protocol TCP -LocalPort 8530 -Action Allow
    New-NetFirewallRule -DisplayName "WSUS HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8531 -Action Allow
    </powershell>
    EOF
  
  tags = {
    Name      = "${var.project_tag}-wsus-2019"
    Role      = "WSUS"
    OS        = "Windows Server 2019"
    PatchGroup = "Windows-Critical"
  }
}

# Windows Server 2019 - WSUS Server
resource "aws_instance" "win_server_2019" {
  count                      = var.create_windows_instances ? 1 : 0
  ami                        = "ami-0ca7038e6ff499fc0" # Windows_Server-2019-English-Full-Base-2026.03.11  |  2026-03-11T19:53:49.000Z
  instance_type              = "t3.medium"
  subnet_id                  = aws_subnet.windows_public_subnet[0].id
  vpc_security_group_ids     = [aws_security_group.windows_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = local.ssm_instance_profile
  
  user_data = <<-EOF
    <script>
    net user ec2-user P@ssw0rd123! /add /fullname:"EC2 User" /comment:"Local admin user"
    net localgroup administrators ec2-user /add
    </powershell>
    EOF
  
  tags = {
    Name      = "${var.project_tag}-win-2019"
    Role      = "WSUS"
    OS        = "Windows Server 2019"
    PatchGroup = "Windows-Critical"
  }
}

# DNS record for WSUS server
resource "aws_route53_record" "wsus" {
  count   = var.create_windows_instances ? 1 : 0
  zone_id = aws_route53_zone.private[0].zone_id
  name    = "wsus.davidawcloudsecurity.com"
  type    = "A"
  ttl     = 300
  records = [aws_instance.wsus_server_2019[0].private_ip]
}


