output "aws_vpc_main" {
  value = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
}

output "aws_subnet_public" {
  value = var.create_vpc ? aws_subnet.public_subnet_01[0].id : null
}

output "aws_subnet_private" {
  value = var.create_vpc ? aws_subnet.private_subnet_01[0].id : null
}

output "wsus_server_public_ip" {
  value = var.enable_windows_instances ? aws_instance.wsus_server_2019[0].public_ip : null
}

output "wsus_server_private_ip" {
  value = var.enable_windows_instances ? aws_instance.wsus_server_2019[0].private_ip : null
}

output "windows_client_public_ip" {
  value = var.enable_windows_instances ? aws_instance.windows_client_2016[0].public_ip : null
}

output "windows_client_private_ip" {
  value = var.enable_windows_instances ? aws_instance.windows_client_2016[0].private_ip : null
}
