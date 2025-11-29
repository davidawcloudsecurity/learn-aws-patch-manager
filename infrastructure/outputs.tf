output "aws_vpc_main" {
  value = aws_vpc.demo_main_vpc.id
}

output "aws_subnet_public" {
  value = aws_subnet.public_subnet_01[*].id
}

output "aws_subnet_private" {
  value = aws_subnet.private_subnet_01[*].id
}
