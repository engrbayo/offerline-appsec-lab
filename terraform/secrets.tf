# JWT signing secret. Value is set out of band (never in Terraform state)
# and rotated every 30 days by a rotation Lambda, not shown in the lab.
resource "aws_secretsmanager_secret" "jwt_signing" {
  name_prefix             = "offerline/jwt-signing-"
  kms_key_id              = aws_kms_key.partner_data.arn
  recovery_window_in_days = 7
}
