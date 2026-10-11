terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40, < 7.0"
    }
  }
}

provider "aws" {
  profile = var.sandbox_profile
  region  = var.region

  default_tags {
    tags = local.common_tags
  }
}
