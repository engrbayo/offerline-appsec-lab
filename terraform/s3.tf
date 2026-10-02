# Landing bucket for bank transaction files (threat model: boundary B1).
resource "aws_s3_bucket" "ingest" {
  bucket_prefix = "offerline-ingest-"
}

resource "aws_s3_bucket_public_access_block" "ingest" {
  bucket                  = aws_s3_bucket.ingest.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    object_ownership = "BucketOwnerEnforced" # disables ACLs; partner uploads become ours
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.partner_data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Data minimization: raw bank files are deleted after 30 days.
resource "aws_s3_bucket_lifecycle_configuration" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  rule {
    id     = "expire-raw-files"
    status = "Enabled"
    filter {
      prefix = "incoming/"
    }
    expiration {
      days = 30
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
  # Checkov CKV_AWS_300 caught that the abort rule only covered incoming/.
  # It now applies bucket-wide, so half-finished uploads anywhere are cleaned up.
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_logging" "ingest" {
  bucket        = aws_s3_bucket.ingest.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "ingest/"
}

resource "aws_s3_bucket_notification" "ingest" {
  bucket      = aws_s3_bucket.ingest.id
  eventbridge = true # new files trigger the ingest worker
}

# Bucket policy: TLS only, KMS only, and each bank may write only under its own prefix.
resource "aws_s3_bucket_policy" "ingest" {
  bucket = aws_s3_bucket.ingest.id
  policy = data.aws_iam_policy_document.ingest_bucket.json
}

data "aws_iam_policy_document" "ingest_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.ingest.arn, "${aws_s3_bucket.ingest.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUploadsWithoutOurKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.ingest.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.partner_data.arn]
    }
  }

  dynamic "statement" {
    for_each = var.bank_partner_role_arns
    content {
      sid       = "PartnerWrite${replace(title(replace(statement.key, "-", " ")), " ", "")}"
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.ingest.arn}/incoming/${statement.key}/*"]
      principals {
        type        = "AWS"
        identifiers = [statement.value]
      }
    }
  }
}

# Access log bucket. Logs are evidence; they are retained longer and nobody but S3 logging writes here.
resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_145: S3 server access logging only delivers to SSE-S3 buckets; SSE-KMS targets are unsupported.
  #checkov:skip=CKV2_AWS_62: Nothing consumes events from the log bucket; notifications would add cost and no control.
  bucket_prefix = "offerline-access-logs-"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # S3 server access logging does not support SSE-KMS targets
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "retain-one-year"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
