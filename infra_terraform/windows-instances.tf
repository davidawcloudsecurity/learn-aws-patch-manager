# Data source for Windows Server AMIs
data "aws_ami" "windows_2019" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base-*"]
  }
}

data "aws_ami" "windows_2016" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["Windows_Server-2016-English-Full-Base-*"]
  }
}

# IAM role for Systems Manager
resource "aws_iam_role" "ssm_role" {
  count = var.create_windows_instances ? 1 : 0
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
  count      = var.create_windows_instances ? 1 : 0
  role       = aws_iam_role.ssm_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
  count = var.create_windows_instances ? 1 : 0
  name  = "${var.project_tag}-ssm-profile"
  role  = aws_iam_role.ssm_role[0].name
}

# Data sources for existing IAM resources
data "aws_iam_role" "existing_ssm_role" {
  count = var.create_windows_instances ? 0 : 1
  name  = "${var.project_tag}-ssm-role"
}

data "aws_iam_instance_profile" "existing_ssm_profile" {
  count = var.create_windows_instances ? 0 : 1
  name  = "${var.project_tag}-ssm-profile"
}

# Security Group for Windows instances
resource "aws_security_group" "windows_sg" {
  count       = var.create_windows_instances ? 1 : 0
  name        = "windows-instances-sg"
  description = "Security group for Windows EC2 instances"
  vpc_id      = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : data.aws_vpc.existing[0].id
  
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 8530
    to_port     = 8531
    protocol    = "tcp"
    cidr_blocks = [var.main_cidr_block]
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

# Data source for existing security group
data "aws_security_group" "existing_windows_sg" {
  count = var.create_windows_instances ? 0 : 1
  name  = "windows-instances-sg"
  vpc_id = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : data.aws_vpc.existing[0].id
}

# Windows Server 2019 - WSUS Server
resource "aws_instance" "wsus_server_2019" {
  count                       = var.create_windows_instances ? 1 : 0
  ami                         = data.aws_ami.windows_2019.id
  instance_type              = "t3.medium"
  subnet_id                  = var.create_vpc ? aws_subnet.public_subnet_01[0].id : data.aws_subnets.existing_public[0].ids[0]
  vpc_security_group_ids     = var.create_windows_instances ? [aws_security_group.windows_sg[0].id] : [data.aws_security_group.existing_windows_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = var.create_windows_instances ? aws_iam_instance_profile.ssm_profile[0].name : data.aws_iam_instance_profile.existing_ssm_profile[0].name
  
  user_data = <<-EOF
    <script>
    net user ec2-user P@ssw0rd123! /add /fullname:"EC2 User" /comment:"Local admin user"
    net localgroup administrators ec2-user /add
    mkdir C:\WSUS\WsusContent
    cd C:\WSUS\WsusContent
    curl -LO https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/11/windows10.0-kb5068791-x64_a8b1b1b6c7b6b673c5a5f32772749eb2bb80c88b.msu
    </script>
    <powershell>    
    # Install WSUS role
    Install-WindowsFeature -Name UpdateServices -IncludeManagementTools
    
    # Create WSUS content directory
    New-Item -Path "C:\WSUS" -ItemType Directory -Force
    
    # Configure WSUS
    & "C:\Program Files\Update Services\Tools\wsusutil.exe" postinstall CONTENT_DIR=C:\WSUS
    
    # Start WSUS services
    Start-Service WsusService
    Set-Service WsusService -StartupType Automatic
    
    # Configure Windows Firewall
    New-NetFirewallRule -DisplayName "WSUS HTTP" -Direction Inbound -Protocol TCP -LocalPort 8530 -Action Allow
    New-NetFirewallRule -DisplayName "WSUS HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8531 -Action Allow
    </powershell>
    EOF
  
  tags = {
    Name = "${var.project_tag}-wsus-2019"
    Role = "WSUS"
    OS   = "Windows Server 2019"
  }
}

# DNS record for WSUS server
resource "aws_route53_record" "wsus" {
  count   = var.create_windows_instances && var.create_route53 ? 1 : 0
  zone_id = var.create_route53 ? aws_route53_zone.private[0].zone_id : data.aws_route53_zone.existing_private[0].zone_id
  name    = "wsus.davidawcloudsecurity.com"
  type    = "A"
  ttl     = 300
  records = var.create_windows_instances ? [aws_instance.wsus_server_2019[0].private_ip] : [data.aws_instance.existing_wsus[0].private_ip]
}

# Data sources for existing resources
data "aws_route53_zone" "existing_private" {
  count        = var.create_route53 ? 0 : 1
  name         = "davidawcloudsecurity.com"
  private_zone = true
}

data "aws_instance" "existing_wsus" {
  count = var.create_windows_instances ? 0 : 1
  
  filter {
    name   = "tag:Name"
    values = ["${var.project_tag}-wsus-2019"]
  }
  
  filter {
    name   = "instance-state-name"
    values = ["running"]
  }
}

# Windows Server 2016 - Client
resource "aws_instance" "windows_client_2016" {
  count                       = var.create_windows_instances ? 1 : 0
  ami                        = "ami-0d8940f0876d45867" # "ami-02f5c360d1593d538" windows 2016
  instance_type              = "t3.small"
  subnet_id                  = var.create_vpc ? aws_subnet.public_subnet_01[0].id : data.aws_subnets.existing_public[0].ids[0]
  vpc_security_group_ids     = var.create_windows_instances ? [aws_security_group.windows_sg[0].id] : [data.aws_security_group.existing_windows_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = var.create_windows_instances ? aws_iam_instance_profile.ssm_profile[0].name : data.aws_iam_instance_profile.existing_ssm_profile[0].name
  
  user_data = <<-EOF
    <powershell>
    # Create local user
    $username = "ec2-user"
    $password = "Letmein2021!" | ConvertTo-SecureString -AsPlainText -Force
    New-LocalUser -Name $username -Password $password -FullName "EC2 User" -Description "Local admin user"
    Add-LocalGroupMember -Group "Administrators" -Member $username
       
    # Set WSUS server URL
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://wsus.davidawcloudsecurity.com:8530" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://wsus.davidawcloudsecurity.com:8530" -Force
    
    # Enable WSUS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 1 -Force
    
    # Configure automatic updates
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3 -Force
    
    # Restart Windows Update service
    Restart-Service wuauserv
    </powershell>
    EOF
  
  depends_on = var.create_windows_instances ? [aws_instance.wsus_server_2019[0], aws_route53_record.wsus[0]] : [data.aws_instance.existing_wsus[0]]
  
  tags = {
    Name = "${var.project_tag}-client-2016"
    Role = "Client"
    OS   = "Windows Server 2016"
  }
}
