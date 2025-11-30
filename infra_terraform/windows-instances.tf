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
  name = "${var.project_tag}-ssm-role"
  
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
  name = "${var.project_tag}-ssm-profile"
  role = aws_iam_role.ssm_role.name
}

# Security Group for Windows instances
resource "aws_security_group" "windows_sg" {
  name        = "windows-instances-sg"
  description = "Security group for Windows EC2 instances"
  vpc_id      = aws_vpc.demo_main_vpc.id
  
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

# Windows Server 2019 - WSUS Server
resource "aws_instance" "wsus_server_2019" {
  ami                         = data.aws_ami.windows_2019.id
  instance_type              = "t3.medium"
  subnet_id                  = aws_subnet.public_subnet_01[0].id
  vpc_security_group_ids     = [aws_security_group.windows_sg.id]
  associate_public_ip_address = true
  iam_instance_profile       = aws_iam_instance_profile.ssm_profile.name
  
  user_data = <<-EOF
    <script>
    net user ec2-user P@ssw0rd123! /add /fullname:"EC2 User" /comment:"Local admin user"
    net localgroup administrators ec2-user /add
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
  zone_id = aws_route53_zone.private.zone_id
  name    = "wsus.davidawcloudsecurity.com"
  type    = "A"
  ttl     = 300
  records = [aws_instance.wsus_server_2019.private_ip]
}

# Windows Server 2016 - Client
resource "aws_instance" "windows_client_2016" {
  ami                        = "ami-02f5c360d1593d538"
  instance_type              = "t3.small"
  subnet_id                  = aws_subnet.public_subnet_01[0].id
  vpc_security_group_ids     = [aws_security_group.windows_sg.id]
  associate_public_ip_address = true
  iam_instance_profile       = aws_iam_instance_profile.ssm_profile.name
  
  user_data = <<-EOF
    <powershell>
    # Create local user
    $username = "ec2-user"
    $password = "Letmein2021!" | ConvertTo-SecureString -AsPlainText -Force
    New-LocalUser -Name $username -Password $password -FullName "EC2 User" -Description "Local admin user"
    Add-LocalGroupMember -Group "Administrators" -Member $username
    
    # Configure WSUS client settings via registry
    $wsusServer = "wsus.davidawcloudsecurity.com"
    
    # Set WSUS server URL
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://$wsusServer:8530" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://$wsusServer:8530" -Force
    
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
  
  depends_on = [aws_instance.wsus_server_2019, aws_route53_record.wsus]
  
  tags = {
    Name = "${var.project_tag}-client-2016"
    Role = "Client"
    OS   = "Windows Server 2016"
  }
}
