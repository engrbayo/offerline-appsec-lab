# DEMO ONLY: deliberately insecure resources to show Checkov and the gate
# catching them. Lives on the demo-vulnerable branch; never merge or apply.

# Public read/write bucket (CKV_AWS_20, CKV_AWS_57: critical in policy.yaml).
resource "aws_s3_bucket" "demo_public" {
  bucket_prefix = "offerline-demo-public-"
}

resource "aws_s3_bucket_acl" "demo_public" {
  bucket = aws_s3_bucket.demo_public.id
  acl    = "public-read-write"
}

# KMS key without rotation (CKV_AWS_7).
resource "aws_kms_key" "demo_no_rotation" {
  description         = "demo key, rotation off"
  enable_key_rotation = false
}

# Admin-everything IAM policy (CKV_AWS_355, CKV_AWS_290).
data "aws_iam_policy_document" "demo_admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "demo_admin" {
  name   = "offerline-demo-admin"
  policy = data.aws_iam_policy_document.demo_admin.json
}

# EC2 with IMDSv1 allowed (CKV_AWS_79) and SSH open to the internet.
resource "aws_security_group" "demo_ssh_open" {
  name = "offerline-demo-ssh-open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "demo_imdsv1" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.demo_ssh_open.id]
  metadata_options {
    http_tokens = "optional"
  }
}
