# ============================================================
# General
# ============================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "use_existing_iam" {
  description = "Create or use existing instance profile role"
  type        = bool
  default     = false
}

variable "create_iam" {
  description = "Set to false to skip IAM role/profile creation (use existing)"
  type        = bool
  default     = true
}

variable "create_s3" {
  description = "Set to false to skip S3 bucket creation (use existing)"
  type        = bool
  default     = true
}

variable "create_efs" {
  description = "Set to false to skip EFS creation (use existing)"
  type        = bool
  default     = true
}

variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "jenkins"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

# ============================================================
# VPC / Networking
# ============================================================

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "172.168.0.0/16"
}

# ============================================================
# EC2 / ASG
# ============================================================

variable "controller_instance_type" {
  description = "Jenkins Controller instance type"
  type        = string
  default     = "t3.large"
}

variable "agent_instance_type" {
  description = "Jenkins Agent instance type"
  type        = string
  default     = "t3.medium"
}

variable "agent_min_size" {
  description = "Min number of Jenkins agents"
  type        = number
  default     = 1
}

variable "agent_max_size" {
  description = "Max number of Jenkins agents"
  type        = number
  default     = 10
}

variable "agent_desired_capacity" {
  description = "Desired number of Jenkins agents"
  type        = number
  default     = 2
}

variable "windows_ami_id" {
  description = "Windows Server 2019 AMI ID (region-specific)"
  type        = string
  default     = "ami-0ca7038e6ff499fc0"
}

# ============================================================
# Secrets
# ============================================================

variable "jenkins_admin_password" {
  description = "Jenkins admin password"
  type        = string
  default     = "JenkinsAdmin123!"
}
