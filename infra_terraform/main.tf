
# Define AWS as the provider with the specified region.
provider "aws" {
  region = var.region # Use the region specified in the variable "region".
}

# Create an AWS VPC with the specified CIDR block and tags.
resource "aws_vpc" "demo_main_vpc" {
  cidr_block           = var.main_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = var.project_tag
  }
}

# Internet Gateway
resource "aws_internet_gateway" "demo_igw" {
  vpc_id = aws_vpc.demo_main_vpc.id
  tags = {
    Name = "${var.project_tag}-igw"
  }
}

# Private hosted zone
resource "aws_route53_zone" "private" {
  name = "davidawcloudsecurity.com"
  
  vpc {
    vpc_id = aws_vpc.demo_main_vpc.id
  }
  
  tags = {
    Name = "${var.project_tag}-private-zone"
  }
}

resource "aws_subnet" "public_subnet_01" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.demo_main_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
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

# Public Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.demo_main_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo_igw.id
  }
  
  tags = {
    Name = "${var.project_tag}-public-rt"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public_rta" {
  count          = length(aws_subnet.public_subnet_01)
  subnet_id      = aws_subnet.public_subnet_01[count.index].id
  route_table_id = aws_route_table.public_rt.id
}
