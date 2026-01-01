region          = "us-east-1"
main_cidr_block = "172.16.0.0/16"
project_tag     = "learn-tf-aws-vpc"

# Conditional resource creation flags
create_vpc               = true
create_windows_instances = true
create_route53          = true
