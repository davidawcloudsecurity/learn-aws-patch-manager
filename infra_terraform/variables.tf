variable "region" {
  description = "Specifies the AWS region."
  type        = string
  default     = "us-east-1"
}

variable "main_cidr_block" {
  description = "Specifies the main CIDR block."
  type        = string
  default     = "172.16.0.0/16"
}

variable "project_tag" {
  description = "Specifies the name tag."
  type        = string
  default     = "learn-tf-aws-vpc"
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Public Subnet CIDR values"
  default     = ["172.16.1.0/24"]
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "Private Subnet CIDR values"
  default     = ["172.16.2.0/24"]
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones"
  default     = ["us-east-1a"]
}
