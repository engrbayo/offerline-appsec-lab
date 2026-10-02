# WAF in front of the partner API (attach to the ALB or API Gateway stage).
# AWS managed rules for common exploits plus a per-IP rate limit. WAF is a
# backstop, not the fix: authorization bugs (IDOR) look like normal traffic.
resource "aws_wafv2_web_acl" "partner_api" {
  name  = "offerline-partner-api"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 10
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet" # includes Log4j patterns
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 30
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 1000 # requests per 5 minutes per IP; partners are servers, not browsers
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "offerline-partner-api"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-offerline-partner-api" # WAF requires this prefix
  retention_in_days = 365
  kms_key_id        = aws_kms_key.partner_data.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "partner_api" {
  resource_arn            = aws_wafv2_web_acl.partner_api.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  redacted_fields {
    single_header {
      name = "authorization" # never write bearer tokens to logs
    }
  }
}
