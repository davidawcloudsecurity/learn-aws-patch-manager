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
  
  tags = {
    Name = "${var.project_tag}-wsus-2019"
    Role = "WSUS"
    OS   = "Windows Server 2019"
  }
}

# Windows Server 2016 - Client
resource "aws_instance" "windows_client_2016" {
  ami                         = data.aws_ami.windows_2016.id
  instance_type              = "t3.small"
  subnet_id                  = aws_subnet.public_subnet_01[0].id
  vpc_security_group_ids     = [aws_security_group.windows_sg.id]
  associate_public_ip_address = true
  
  tags = {
    Name = "${var.project_tag}-client-2016"
    Role = "Client"
    OS   = "Windows Server 2016"
  }
}
