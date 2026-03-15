output "aws_vpc_rhel" {
  value = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
}

output "aws_vpc_windows" {
  value = var.create_vpc ? aws_vpc.windows_vpc[0].id : null
}

output "aws_subnet_rhel_public" {
  value = var.create_vpc ? aws_subnet.public_subnet_01[0].id : null
}

output "aws_subnet_rhel_private" {
  value = var.create_vpc ? aws_subnet.private_subnet_01[0].id : null
}

output "aws_subnet_windows_public" {
  value = var.create_vpc ? aws_subnet.windows_public_subnet[0].id : null
}

output "aws_subnet_windows_private" {
  value = var.create_vpc ? aws_subnet.windows_private_subnet[0].id : null
}

output "tgw_inbound_id" {
  value = var.create_tgw ? aws_ec2_transit_gateway.tgw_inbound[0].id : null
}

output "tgw_outbound_id" {
  value = var.create_tgw ? aws_ec2_transit_gateway.tgw_outbound[0].id : null
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
