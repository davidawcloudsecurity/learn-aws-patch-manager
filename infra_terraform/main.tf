
# Define AWS as the provider with the specified region.
provider "aws" {
  region = var.region # Use the region specified in the variable "region".
}

# Create an AWS VPC with the specified CIDR block and tags.
resource "aws_vpc" "demo_main_vpc" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.main_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = var.project_tag
  }
}

# Internet Gateway
resource "aws_internet_gateway" "demo_igw" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
  tags = {
    Name = "${var.project_tag}-igw"
  }
}

# Private hosted zone
resource "aws_route53_zone" "private" {
  count = var.create_route53 ? 1 : 0
  name  = "davidawcloudsecurity.com"
  
  vpc {
    vpc_id = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : data.aws_vpc.existing[0].id
  }
  
  tags = {
    Name = "${var.project_tag}-private-zone"
  }
}

# Data source for existing VPC (when not creating new one)
data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  
  filter {
    name   = "tag:Name"
    values = [var.project_tag]
  }
}

resource "aws_subnet" "public_subnet_01" {
  count                   = var.create_vpc ? length(var.public_subnet_cidrs) : 0
  vpc_id                  = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_tag}-pb-sub-01"
  }
}

# Data source for existing public subnets
data "aws_subnets" "existing_public" {
  count = var.create_vpc ? 0 : 1
  
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.existing[0].id]
  }
  
  filter {
    name   = "tag:Name"
    values = ["${var.project_tag}-pb-sub-01"]
  }
}

resource "aws_subnet" "private_subnet_01" {
  count             = var.create_vpc ? length(var.private_subnet_cidrs) : 0
  vpc_id            = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = {
    Name = "${var.project_tag}-pv-sub-01"
  }
}

# Public Route Table
resource "aws_route_table" "public_rt" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = var.create_vpc ? aws_vpc.demo_main_vpc[0].id : null
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = var.create_vpc ? aws_internet_gateway.demo_igw[0].id : null
  }
  
  tags = {
    Name = "${var.project_tag}-public-rt"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public_rta" {
  count          = var.create_vpc ? length(aws_subnet.public_subnet_01) : 0
  subnet_id      = aws_subnet.public_subnet_01[count.index].id
  route_table_id = aws_route_table.public_rt[0].id
}
