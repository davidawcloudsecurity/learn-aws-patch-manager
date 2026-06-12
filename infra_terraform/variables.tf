# ============================================================
# General
# ============================================================

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_tag" {
  description = "Project name tag used for all resources"
  type        = string
  default     = "learn-patch-asg-ad"
}

# ============================================================
# VPC / Networking
# ============================================================

variable "main_cidr_block" {
  description = "VPC CIDR block"
  type        = string
  default     = "172.16.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs (one per AZ)"
  type        = list(string)
  default     = ["172.16.1.0/24", "172.16.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (need 2 AZs for Managed AD)"
  type        = list(string)
  default     = ["172.16.2.0/24", "172.16.4.0/24"]
}

variable "azs" {
  description = "Availability Zones (minimum 2 for Managed AD)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "custom_ami_id" {
  description = "Custom AMI ID for the ASG. Leave empty to use latest Windows Server 2019 from Amazon."
  type        = string
  # default     = "ami-0ca7038e6ff499fc0"
  default     = "ami-075309a66c5dedf22"
}

# ami-073ed03c725f813eb|  Windows_Server-2019-English-Full-Base-2026.05.13  |  2026-05-13T19:00:53.000Z  |
# ami-075309a66c5dedf22|  Windows_Server-2019-English-Full-Base-2026.04.15  |  2026-04-16T01:39:19.000Z  |

variable "create_vpc" {
  description = "Whether to create VPC resources (false = use existing)"
  type        = bool
  default     = true
}

variable "use_existing_iam" {
  description = "Legacy variable (unused, kept for tfvars compatibility)"
  type        = bool
  default     = false
}

# ============================================================
# AWS Managed Microsoft AD
# ============================================================

variable "ad_domain_name" {
  description = "FQDN for the AWS Managed Microsoft AD"
  type        = string
  default     = "corp.learn-patch.local"
}

variable "ad_admin_password" {
  description = "Admin password for Managed AD (set via TF_VAR_ad_admin_password env var)"
  type        = string
  sensitive   = true
}

variable "ad_edition" {
  description = "Managed AD edition: Standard or Enterprise"
  type        = string
  default     = "Standard"
}

# ============================================================
# Windows ASG
# ============================================================

variable "windows_instance_type" {
  description = "Instance type for Windows ASG instances"
  type        = string
  default     = "t3.medium"
}

variable "asg_desired_capacity" {
  description = "Desired number of instances in the ASG"
  type        = number
  default     = 2
}

variable "asg_min_size" {
  description = "Minimum ASG size"
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Maximum ASG size"
  type        = number
  default     = 4
}

# ============================================================
# Linux Ubuntu Standalone
# ============================================================

variable "linux_instance_type" {
  description = "Instance type for the Linux Ubuntu standalone instance"
  type        = string
  default     = "t3.medium"
}

variable "custom_linux_ami_id" {
  description = "Custom AMI ID for the Linux instance. Leave empty to use latest Ubuntu 22.04 from Canonical."
  type        = string
  default     = ""
}

# ============================================================
# SSM Patch Manager
# ============================================================

variable "patch_schedule" {
  description = "Cron expression for the patch maintenance window (UTC)"
  type        = string
  default     = "cron(0 2 ? * SUN *)"
}

variable "patch_window_duration" {
  description = "Maintenance window duration in hours"
  type        = number
  default     = 3
}

variable "patch_window_cutoff" {
  description = "Hours before window end to stop scheduling new tasks"
  type        = number
  default     = 1
}
