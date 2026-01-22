# Variable to enable/disable RHEL instances
variable "enable_rhel_instances" {
  description = "Enable RHEL instances deployment"
  type        = bool
  default     = true
}

# Data source for RHEL 9 AMI
data "aws_ami" "rhel_9" {
  count       = var.enable_rhel_instances ? 1 : 0
  most_recent = true
  owners      = ["309956199498"] # Red Hat
  
  filter {
    name   = "name"
    values = ["RHEL-9.*-x86_64-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Data source for RHEL 8 AMI
data "aws_ami" "rhel_8" {
  count       = var.enable_rhel_instances ? 1 : 0
  most_recent = true
  owners      = ["309956199498"] # Red Hat
  
  filter {
    name   = "name"
    values = ["RHEL-8.*-x86_64-*"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Security Group for RHEL instances
resource "aws_security_group" "rhel_sg" {
  count       = var.enable_rhel_instances ? 1 : 0
  name        = "rhel-instances-sg"
  description = "Security group for RHEL EC2 instances"
  vpc_id      = aws_vpc.demo_main_vpc[0].id
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.project_tag}-rhel-sg"
  }
}

# RHEL 9 instance
resource "aws_instance" "rhel_9_server" {
  count                      = var.enable_rhel_instances ? 1 : 0
  ami                        = "ami-0d8d3b1122e36c000" # data.aws_ami.rhel_9[0].id
  instance_type              = "t3.small"
  subnet_id                  = aws_subnet.public_subnet_01[0].id
  vpc_security_group_ids     = [aws_security_group.rhel_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = local.ssm_instance_profile
  
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent
    EOF
  
  tags = {
    Name      = "${var.project_tag}-rhel-9"
    Role      = "Server"
    OS        = "RHEL 9"
    PatchGroup = "RHEL-Critical"
  }
}

# RHEL 8 instance
resource "aws_instance" "rhel_8_client" {
  count                      = var.enable_rhel_instances ? 1 : 0
  ami                        = data.aws_ami.rhel_8[0].id
  instance_type              = "t3.small"
  subnet_id                  = aws_subnet.public_subnet_01[0].id
  vpc_security_group_ids     = [aws_security_group.rhel_sg[0].id]
  associate_public_ip_address = true
  iam_instance_profile       = local.ssm_instance_profile
  
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent
    EOF
  
  tags = {
    Name      = "${var.project_tag}-rhel-8"
    Role      = "Client"
    OS        = "RHEL 8"
    PatchGroup = "RHEL-Critical"
  }
}
