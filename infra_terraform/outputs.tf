output "aws_vpc_rhel" {
  value = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
}

output "aws_vpc_windows" {
  value = var.create_vpc ? aws_vpc.windows_vpc[0].id : null
}

output "aws_subnet_rhel_public" {
  value       = var.create_vpc ? aws_subnet.public_subnet_01[*].id : null
  description = "RHEL VPC public subnet IDs (one per AZ)"
}

output "aws_subnet_rhel_private" {
  value       = var.create_vpc ? aws_subnet.private_subnet_01[*].id : null
  description = "RHEL VPC private subnet IDs (one per AZ)"
}

output "aws_subnet_windows_public" {
  value       = var.create_vpc ? aws_subnet.windows_public_subnet[*].id : null
  description = "Windows VPC public subnet IDs (one per AZ)"
}

output "aws_subnet_windows_private" {
  value       = var.create_vpc ? aws_subnet.windows_private_subnet[*].id : null
  description = "Windows VPC private subnet IDs (one per AZ)"
}

output "tgw_inbound_id" {
  value = var.create_tgw ? aws_ec2_transit_gateway.tgw_inbound[0].id : null
}

output "tgw_outbound_id" {
  value = var.create_tgw ? aws_ec2_transit_gateway.tgw_outbound[0].id : null
}

output "tgw_inbound_route_table_id" {
  value       = var.create_tgw ? aws_ec2_transit_gateway.tgw_inbound[0].association_default_route_table_id : null
  description = "TGW inbound default route table ID"
}

output "tgw_outbound_route_table_id" {
  value       = var.create_tgw ? aws_ec2_transit_gateway.tgw_outbound[0].association_default_route_table_id : null
  description = "TGW outbound default route table ID"
}

output "rhel_instance_ips" {
  value       = var.enable_rhel_instances ? aws_instance.rhel_9_server[*].private_ip : null
  description = "RHEL instance private IPs"
}

output "wsus_server_public_ip" {
  value = var.create_windows_instances ? aws_instance.wsus_server_2019[*].public_ip : null
}

output "wsus_server_private_ip" {
  value = var.create_windows_instances ? aws_instance.wsus_server_2019[*].private_ip : null
}
