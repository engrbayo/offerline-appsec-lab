# One customer-managed key for partner data. Key policy is explicit: account
# root keeps admin (so the key can't be orphaned) and only the ingest worker
# and partner upload roles can use it for data.
resource "aws_kms_key" "partner_data" {
  description             = "Offerline partner transaction data"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms_partner_data.json
}

resource "aws_kms_alias" "partner_data" {
  name          = "alias/offerline-partner-data"
  target_key_id = aws_kms_key.partner_data.key_id
}

data "aws_iam_policy_document" "kms_partner_data" {
  # False positives: in a KMS *key policy*, Resource "*" means "this key", not
  # every resource in the account. The generic IAM checks can't tell a key
  # policy from an identity policy.
  #checkov:skip=CKV_AWS_109: key policy; "*" is scoped to this key
  #checkov:skip=CKV_AWS_111: key policy; "*" is scoped to this key
  #checkov:skip=CKV_AWS_356: key policy; "*" is scoped to this key
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"] # in a key policy, "*" means this key
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "IngestWorkerDecrypt"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.ingest_worker.arn]
    }
  }

  dynamic "statement" {
    for_each = length(var.bank_partner_role_arns) > 0 ? [1] : []
    content {
      sid       = "PartnersEncryptOnUpload"
      actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = values(var.bank_partner_role_arns)
      }
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${var.region}.amazonaws.com"]
      }
    }
  }
}
