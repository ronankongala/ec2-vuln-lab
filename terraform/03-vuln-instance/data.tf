data "terraform_remote_state" "guardrails" {
  backend = "local"

  config = {
    path = "${path.module}/../02-guardrails-sandbox/terraform.tfstate"
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# If account-level EBS default encryption is on, AWS encrypts the root volume
# regardless of encrypted = false, and the CLD-05 finding will not reproduce.
data "aws_ebs_encryption_by_default" "current" {}

# S3 managed prefix list, used for egress to package repos via the gateway endpoint.
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.region}.s3"
}

data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# INTENTIONAL FINDING CLD-06: wildcard S3 permissions on all resources.
data "aws_iam_policy_document" "overly_permissive_s3" {
  statement {
    sid       = "IntentionalCLD06"
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
  }
}
