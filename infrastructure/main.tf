
# Define AWS as the provider with the specified region.
provider "aws" {
  region = var.region # Use the region specified in the variable "region".
}

# Create an AWS VPC with the specified CIDR block and tags.
resource "aws_vpc" "demo_main_vpc" {
  cidr_block = var.main_cidr_block # Set the CIDR block for the VPC.
  tags = {
    Name = var.project_tag # Assign the project tag to the VPC.
  }
}

resource "aws_subnet" "public_subnet_01" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.demo_main_vpc.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = {
    Name = "${var.project_tag}-pb-sub-01"
  }
}

resource "aws_subnet" "private_subnet_01" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.demo_main_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = {
    Name = "${var.project_tag}-pv-sub-01"
  }
}