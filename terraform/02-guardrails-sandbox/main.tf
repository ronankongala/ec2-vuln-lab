locals {
  common_tags = {
    Project = "ec2-vuln-lab"
    Purpose = "intentionally-vulnerable-lab"
  }

  vpc_cidr            = "10.50.0.0/16"
  private_subnet_cidr = "10.50.1.0/24"
  availability_zone   = coalesce(var.availability_zone, data.aws_availability_zones.available.names[0])

  # Interface endpoints required for SSM Session Manager without internet access.
  ssm_interface_endpoints = toset(["ssm", "ssmmessages", "ec2messages"])
}

data "aws_availability_zones" "available" {
  state = "available"
}

# -----------------------------------------------------------------------------
# Budget
# -----------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly_cost" {
  name         = "ec2-vuln-lab-monthly-cost"
  budget_type  = "COST"
  limit_amount = format("%.2f", var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# -----------------------------------------------------------------------------
# Network: isolated VPC, one private subnet, no IGW / NAT / public subnet.
# VPC flow logs are intentionally NOT enabled (planned finding).
# -----------------------------------------------------------------------------
resource "aws_vpc" "lab" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true # required for interface endpoint private DNS
  enable_dns_hostnames = true # required for interface endpoint private DNS

  tags = {
    Name = "vuln-lab-vpc"
  }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = local.private_subnet_cidr
  availability_zone       = local.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "vuln-lab-private-subnet"
  }
}

# Only the implicit local route plus the S3 gateway endpoint route (added by
# aws_vpc_endpoint.s3 below). No default route anywhere.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "vuln-lab-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# -----------------------------------------------------------------------------
# VPC endpoints
# -----------------------------------------------------------------------------

# S3 gateway endpoint: needed for Amazon Linux 2023 package repos (dnf).
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.lab.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "vuln-lab-s3-gateway-endpoint"
  }
}

resource "aws_security_group" "endpoints" {
  name        = "vuln-lab-vpce-sg"
  description = "HTTPS from inside vuln-lab-vpc to SSM interface endpoints"
  vpc_id      = aws_vpc.lab.id

  # No egress rules: Terraform removes the AWS default allow-all egress rule.
  # Interface endpoints only need to accept inbound connections.

  tags = {
    Name = "vuln-lab-vpce-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from vuln-lab-vpc"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.vpc_cidr

  tags = {
    Name = "vuln-lab-vpce-https-in"
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = local.ssm_interface_endpoints

  vpc_id              = aws_vpc.lab.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "vuln-lab-${each.key}-endpoint"
  }
}
