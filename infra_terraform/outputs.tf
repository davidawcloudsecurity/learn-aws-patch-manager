output "aws_vpc_main" {
  value = aws_vpc.demo_main_vpc.id
}

output "aws_subnet_public" {
  value = aws_subnet.public_subnet_01[*].id
}

output "aws_subnet_private" {
  value = aws_subnet.private_subnet_01[*].id
}

output "wsus_server_public_ip" {
  value = aws_instance.wsus_server_2019.public_ip
}

output "wsus_server_private_ip" {
  value = aws_instance.wsus_server_2019.private_ip
}

output "windows_client_public_ip" {
  value = aws_instance.windows_client_2016.public_ip
}

output "windows_client_private_ip" {
  value = aws_instance.windows_client_2016.private_ip
}
