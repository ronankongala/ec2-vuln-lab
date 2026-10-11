locals {
  common_tags = {
    Project = "ec2-vuln-lab"
    Purpose = "intentionally-vulnerable-lab"
  }

  vpc_id            = data.terraform_remote_state.guardrails.outputs.vpc_id
  private_subnet_id = data.terraform_remote_state.guardrails.outputs.private_subnet_id
  availability_zone = data.terraform_remote_state.guardrails.outputs.availability_zone
  vpc_cidr          = "10.50.0.0/16"

  # The real bootstrap script replaces this placeholder in the next session.
  bootstrap_path   = "${path.module}/../../bootstrap/vulnerable-setup.sh"
  bootstrap_script = fileexists(local.bootstrap_path) ? file(local.bootstrap_path) : "#!/bin/bash\necho placeholder"

  # INTENTIONAL FINDING CLD-07: plaintext secret in user_data.
  # Inserted directly after the shebang; cloud-init only runs user_data as a
  # script when the first line is "#!", so it cannot go on line 1.
  user_data = join("\n", [
    "#!/bin/bash",
    "export DB_ADMIN_PASSWORD=\"LAB-FAKE-SuperSecret123\"",
    replace(local.bootstrap_script, "/^#![^\n]*\n/", ""),
  ])
}

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

resource "aws_iam_role" "target" {
  name               = "vuln-lab-target-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.target.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# INTENTIONAL FINDING CLD-06
resource "aws_iam_role_policy" "overly_permissive_s3" {
  name   = "overly-permissive-s3"
  role   = aws_iam_role.target.id
  policy = data.aws_iam_policy_document.overly_permissive_s3.json
}

resource "aws_iam_instance_profile" "target" {
  name = "vuln-lab-target-role"
  role = aws_iam_role.target.name
}

# ---------------------------------------------------------------------------
# Security group
# ---------------------------------------------------------------------------

# No inline rules: Terraform removes AWS's default allow-all egress rule when
# it creates the group, so only the rules below exist.
resource "aws_security_group" "target" {
  name        = "vuln-lab-target-sg"
  description = "Intentionally permissive SG for the vulnerable lab target"
  vpc_id      = local.vpc_id

  tags = {
    Name = "vuln-lab-target-sg"
  }
}

# INTENTIONAL FINDINGS CLD-02 (22), CLD-03 (3306), CLD-04 (6379).
# Unreachable in practice: the subnet has no internet path.
resource "aws_vpc_security_group_ingress_rule" "open" {
  for_each = {
    ssh   = 22
    mysql = 3306
    redis = 6379
  }

  security_group_id = aws_security_group.target.id
  description       = "INTENTIONAL: ${each.key} open to 0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "vuln-lab-target-${each.key}-open"
  }
}

resource "aws_vpc_security_group_egress_rule" "https_vpc" {
  security_group_id = aws_security_group.target.id
  description       = "HTTPS to SSM interface endpoints in the lab VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.vpc_cidr

  tags = {
    Name = "vuln-lab-target-https-vpc"
  }
}

resource "aws_vpc_security_group_egress_rule" "https_s3" {
  security_group_id = aws_security_group.target.id
  description       = "HTTPS to S3 via the gateway endpoint (package repos)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_prefix_list.s3.id

  tags = {
    Name = "vuln-lab-target-https-s3"
  }
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------

resource "aws_instance" "target" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro" # SCP denies every other type
  subnet_id                   = local.private_subnet_id
  availability_zone           = local.availability_zone
  vpc_security_group_ids      = [aws_security_group.target.id]
  iam_instance_profile        = aws_iam_instance_profile.target.name
  associate_public_ip_address = false
  monitoring                  = false # INTENTIONAL FINDING CLD-09

  user_data                   = local.user_data
  user_data_replace_on_change = true

  # INTENTIONAL FINDING CLD-01: IMDSv1 allowed.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # INTENTIONAL FINDING CLD-05: unencrypted root volume.
  root_block_device {
    volume_size           = 12
    volume_type           = "gp3"
    encrypted             = false
    delete_on_termination = true
  }

  lifecycle {
    # Don't replace the instance every time a newer AL2023 AMI is published.
    ignore_changes = [ami]
  }

  tags = {
    Name = "vuln-lab-target"
  }
}
