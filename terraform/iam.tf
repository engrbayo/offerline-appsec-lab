# Ingest worker (ECS task). Least privilege: read one prefix, decrypt with one
# key, read one secret. No wildcards on resources or actions.
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id] # confused-deputy guard
    }
  }
}

resource "aws_iam_role" "ingest_worker" {
  name_prefix          = "offerline-ingest-"
  assume_role_policy   = data.aws_iam_policy_document.ecs_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "ingest_worker" {
  statement {
    sid       = "ReadIncomingFiles"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.ingest.arn}/incoming/*"]
  }
  statement {
    sid       = "ListIncoming"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.ingest.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["incoming/*"]
    }
  }
  statement {
    sid       = "DecryptPartnerData"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.partner_data.arn]
  }
  statement {
    sid       = "ReadJwtSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.jwt_signing.arn]
  }
}

resource "aws_iam_role_policy" "ingest_worker" {
  name   = "least-privilege"
  role   = aws_iam_role.ingest_worker.id
  policy = data.aws_iam_policy_document.ingest_worker.json
}
