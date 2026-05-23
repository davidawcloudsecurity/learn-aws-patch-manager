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

variable "create_vpc" {
  description = "Whether to create VPC resources (false = use existing)"
  type        = bool
  default     = true
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
