terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.70" }
  }
  # Remote state with encryption and locking; state can contain secrets.
  # backend "s3" { bucket = "offerline-tfstate", key = "appsec-lab/terraform.tfstate", region = "us-east-1", encrypt = true, use_lockfile = true }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "offerline", owner = "appsec", data_class = "confidential" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
