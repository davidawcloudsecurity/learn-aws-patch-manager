region          = "us-east-1"
project_tag     = "learn-patch-asg-ad"
main_cidr_block = "172.16.0.0/16"

# VPC
create_vpc = true

use_existing_iam = false

# Managed AD
ad_domain_name = "corp.learn-patch.local"
ad_edition     = "Standard"
ad_admin_password ="YourP@ssw0rd!"
# ad_admin_password — set via: export TF_VAR_ad_admin_password='YourP@ssw0rd!'

# ASG
windows_instance_type = "t3.medium"
asg_desired_capacity  = 2
asg_min_size          = 1
asg_max_size          = 4

# Patch Manager — Every Sunday at 2 AM UTC
patch_schedule        = "cron(0 2 ? * SUN *)"
patch_window_duration = 3
patch_window_cutoff   = 1
