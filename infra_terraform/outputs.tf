output "aws_vpc_main" {
  value = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : data.aws_vpc.existing[0].id
}

output "aws_subnet_public" {
  value = var.create_vpc ? aws_subnet.public_subnet_01[*].id : data.aws_subnets.existing_public[0].ids
}

output "aws_subnet_private" {
  value = var.create_vpc ? aws_subnet.private_subnet_01[*].id : []
}

output "wsus_server_public_ip" {
  value = var.create_windows_instances ? aws_instance.wsus_server_2019[0].public_ip : data.aws_instance.existing_wsus[0].public_ip
}

output "wsus_server_private_ip" {
  value = var.create_windows_instances ? aws_instance.wsus_server_2019[0].private_ip : data.aws_instance.existing_wsus[0].private_ip
}

output "windows_client_public_ip" {
  value = var.create_windows_instances ? aws_instance.windows_client_2016[0].public_ip : null
}

output "windows_client_private_ip" {
  value = var.create_windows_instances ? aws_instance.windows_client_2016[0].private_ip : null
}
