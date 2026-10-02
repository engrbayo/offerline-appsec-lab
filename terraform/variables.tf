variable "region" {
  type    = string
  default = "us-east-1"
}

variable "github_repo" {
  description = "owner/name of the repo allowed to deploy, e.g. your-user/offerline-appsec-lab"
  type        = string
}

variable "bank_partner_role_arns" {
  description = "Per-tenant IAM roles in each bank's AWS account allowed to drop files, keyed by tenant id"
  type        = map(string)
  default     = {}
}
