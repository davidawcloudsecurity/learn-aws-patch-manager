# Define AWS as the provider with the specified region.
provider "aws" {
  region = var.region
}

# -------------------------------------------------------
# VPC-1: RHEL (172.16.0.0/16)
# -------------------------------------------------------
resource "aws_vpc" "demo_main_vpc" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.main_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${var.project_tag}-rhel-vpc"
  }
}

resource "aws_internet_gateway" "demo_igw" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.demo_main_vpc[0].id
  tags = {
    Name = "${var.project_tag}-rhel-igw"
  }
}

resource "aws_subnet" "public_subnet_01" {
  count                   = var.create_vpc ? length(var.public_subnet_cidrs) : 0
  vpc_id                  = aws_vpc.demo_main_vpc[0].id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_tag}-rhel-pb-sub-01"
  }
}

resource "aws_subnet" "private_subnet_01" {
  count             = var.create_vpc ? length(var.private_subnet_cidrs) : 0
  vpc_id            = aws_vpc.demo_main_vpc[0].id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = {
    Name = "${var.project_tag}-rhel-pv-sub-01"
  }
}

resource "aws_route_table" "public_rt" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.demo_main_vpc[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo_igw[0].id
  }

  tags = {
    Name = "${var.project_tag}-rhel-public-rt"
  }
}

resource "aws_route_table_association" "public_rta" {
  count          = var.create_vpc ? length(aws_subnet.public_subnet_01) : 0
  subnet_id      = aws_subnet.public_subnet_01[count.index].id
  route_table_id = aws_route_table.public_rt[0].id
}

# -------------------------------------------------------
# VPC-2: Windows WSUS (172.17.0.0/16)
# -------------------------------------------------------
resource "aws_vpc" "windows_vpc" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.windows_vpc_cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${var.project_tag}-windows-vpc"
  }
}

resource "aws_internet_gateway" "windows_igw" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.windows_vpc[0].id
  tags = {
    Name = "${var.project_tag}-windows-igw"
  }
}

resource "aws_subnet" "windows_public_subnet" {
  count                   = var.create_vpc ? length(var.windows_vpc_public_subnet_cidrs) : 0
  vpc_id                  = aws_vpc.windows_vpc[0].id
  cidr_block              = var.windows_vpc_public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project_tag}-windows-pb-sub-01"
  }
}

resource "aws_subnet" "windows_private_subnet" {
  count             = var.create_vpc ? length(var.windows_vpc_private_subnet_cidrs) : 0
  vpc_id            = aws_vpc.windows_vpc[0].id
  cidr_block        = var.windows_vpc_private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  tags = {
    Name = "${var.project_tag}-windows-pv-sub-01"
  }
}

resource "aws_route_table" "windows_public_rt" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.windows_vpc[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.windows_igw[0].id
  }

  tags = {
    Name = "${var.project_tag}-windows-public-rt"
  }
}

resource "aws_route_table_association" "windows_public_rta" {
  count          = var.create_vpc ? length(aws_subnet.windows_public_subnet) : 0
  subnet_id      = aws_subnet.windows_public_subnet[count.index].id
  route_table_id = aws_route_table.windows_public_rt[0].id
}

# -------------------------------------------------------
# Transit Gateway - Inbound
# -------------------------------------------------------
resource "aws_ec2_transit_gateway" "tgw_inbound" {
  count       = var.create_tgw ? 1 : 0
  description = "Inbound Transit Gateway"
  tags = {
    Name = "${var.project_tag}-tgw-inbound"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_inbound_rhel" {
  count              = var.create_tgw && var.create_vpc ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.tgw_inbound[0].id
  vpc_id             = aws_vpc.demo_main_vpc[0].id
  subnet_ids         = [aws_subnet.public_subnet_01[0].id]
  tags = {
    Name = "${var.project_tag}-tgw-inbound-rhel-attach"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_inbound_windows" {
  count              = var.create_tgw && var.create_vpc ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.tgw_inbound[0].id
  vpc_id             = aws_vpc.windows_vpc[0].id
  subnet_ids         = [aws_subnet.windows_public_subnet[0].id]
  tags = {
    Name = "${var.project_tag}-tgw-inbound-windows-attach"
  }
}

# -------------------------------------------------------
# Transit Gateway - Outbound
# -------------------------------------------------------
resource "aws_ec2_transit_gateway" "tgw_outbound" {
  count       = var.create_tgw ? 1 : 0
  description = "Outbound Transit Gateway"
  tags = {
    Name = "${var.project_tag}-tgw-outbound"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_outbound_rhel" {
  count              = var.create_tgw && var.create_vpc ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.tgw_outbound[0].id
  vpc_id             = aws_vpc.demo_main_vpc[0].id
  subnet_ids         = [aws_subnet.public_subnet_01[0].id]
  tags = {
    Name = "${var.project_tag}-tgw-outbound-rhel-attach"
  }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "tgw_outbound_windows" {
  count              = var.create_tgw && var.create_vpc ? 1 : 0
  transit_gateway_id = aws_ec2_transit_gateway.tgw_outbound[0].id
  vpc_id             = aws_vpc.windows_vpc[0].id
  subnet_ids         = [aws_subnet.windows_public_subnet[0].id]
  tags = {
    Name = "${var.project_tag}-tgw-outbound-windows-attach"
  }
}

# -------------------------------------------------------
# Route53 Private Zone (attached to VPC-1)
# -------------------------------------------------------
resource "aws_route53_zone" "private" {
  count = var.create_route53 ? 1 : 0
  name  = "davidawcloudsecurity.com"

  vpc {
    vpc_id = aws_vpc.demo_main_vpc[0].id
  }

  tags = {
    Name = "${var.project_tag}-private-zone"
  }
}

# -------------------------------------------------------
# Data sources for existing resources (when create_vpc=false)
# -------------------------------------------------------
data "aws_vpc" "existing" {
  count = var.create_vpc ? 0 : 1
  filter {
    name   = "tag:Name"
    values = ["${var.project_tag}-rhel-vpc"]
  }
}

data "aws_subnets" "existing_public" {
  count = var.create_vpc ? 0 : 1
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.existing[0].id]
  }
  filter {
    name   = "tag:Name"
    values = ["${var.project_tag}-rhel-pb-sub-01"]
  }
}
