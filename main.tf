data "aws_caller_identity" "current" {}

######################################################################
# Create CloudTrail
######################################################################
resource "aws_cloudtrail" "cloudtrail" {
  name                          = "${var.prefix}-cloudtrail"
  enable_logging                = true
  s3_bucket_name                = "${aws_s3_bucket.cloudtrail_log_bucket.id}"
  enable_log_file_validation    = true
  is_multi_region_trail         = false
  include_global_service_events = true
  cloud_watch_logs_role_arn     = "${aws_iam_role.cloudtrail_cloudwatch_role.arn}"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudwatch_log_group.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

}

######################################################################
# Create key to encypt CloudTrail logs in S3 bucket 
######################################################################
resource "aws_kms_key" "cloudtrail_log_bucket_key" {
  description             = "KMS key to encypt data within CloudTrail S3 Bucket"
  enable_key_rotation     = true
}

######################################################################
# Create S3 bucket for CloudTrail
######################################################################
resource "aws_s3_bucket" "cloudtrail_log_bucket" {
  bucket = "${var.prefix}-cloudtrail-log-bucket"
  region        = "${var.region}"
  force_destroy = true

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = false
  }

  lifecycle_rule {
    enabled = true

    expiration {
      days = 90
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.cloudtrail_log_bucket_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_log_bucket_policy" {
  bucket = "${aws_s3_bucket.cloudtrail_log_bucket.id}"
  policy = "${data.aws_iam_policy_document.default.json}"
}

data "aws_iam_policy_document" "default" {

  statement {
    sid = "AWSCloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "${aws_s3_bucket.cloudtrail_log_bucket.arn}",
    ]
  }

  statement {
    sid = "AWSCloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com", "cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.cloudtrail_log_bucket.arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

######################################################################
# Create CloudWatch log group
######################################################################
resource "aws_cloudwatch_log_group" "cloudwatch_log_group" {
  name = "${var.prefix}-cloudwatch_log_group"
  retention_in_days = 14
}


######################################################################
# Create link between CloudTrail and CloudWatch
######################################################################
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name               = "${var.prefix}-cloudtrail_cloudwatch_role"
  assume_role_policy = "${data.aws_iam_policy_document.assume_policy.json}"
  provisioner "local-exec" {
      command = "sleep 20"
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name        = "${var.prefix}-cloudtrail_cloudwatch_policy"
  role        = "${aws_iam_role.cloudtrail_cloudwatch_role.id}"
  policy      = "${data.aws_iam_policy_document.cloudtrail_cloudwatch_policy_document.json}"
}


data "aws_iam_policy_document" "cloudtrail_cloudwatch_policy_document" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogStream"]

    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudwatch_log_group.name}:log-stream:*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]

    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.cloudwatch_log_group.name}:log-stream:*",
    ]
  }
}

data "aws_iam_policy_document" "assume_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

######################################################################
# Create Elasticsearch domain
######################################################################
resource "aws_elasticsearch_domain" "elasticsearch-domain" {
  domain_name           = "${var.prefix}-elasticsearch-domain"
  elasticsearch_version = "${var.es_version}"

  cluster_config {
    instance_type  = "${var.es_instance_type}"
    instance_count = "${var.es_instance_count}"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

}

resource "aws_elasticsearch_domain_policy" "main" {
  domain_name = "${aws_elasticsearch_domain.elasticsearch-domain.domain_name}"

  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "${var.es_management_public_ip_address}"
        }
      },
      "Resource": "${aws_elasticsearch_domain.elasticsearch-domain.arn}/*"
    }
  ]
}
POLICIES
}

######################################################################
# Create Lambda to export the logs from CloudWatch log group to Elasticsearch
######################################################################
resource "aws_iam_role" "lambda-es-role" {
  name = "${var.prefix}-lambda-es-role"
  provisioner "local-exec" {
      command = "sleep 20"
  }

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "lambda-es-policy" {
  name = "${var.prefix}-lambda-es-policy"
  role = "${aws_iam_role.lambda-es-role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:*:*:*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "es:ESHttpPost",
      "Resource": "arn:aws:es:*:*:*"
    }
  ]
}
EOF
}



resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.LogsToElasticsearch.arn}"
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudwatch_log_group.arn}"
}

resource "aws_cloudwatch_log_subscription_filter" "lambdafunction_logfilter" {
  depends_on      = ["aws_lambda_permission.allow_cloudwatch"]

  name            = "lambdafunction_logfilter"
  log_group_name  = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"
  filter_pattern  = "event"
  destination_arn = "${aws_lambda_function.LogsToElasticsearch.arn}"
}

resource "aws_lambda_alias" "lambda_alias" {
  name             = "${var.prefix}-LogsToElasticsearch-Alias"
  function_name    = "${aws_lambda_function.LogsToElasticsearch.function_name}"
  function_version = "$LATEST"
}

resource "aws_lambda_function" "LogsToElasticsearch" {
  filename         = "${path.module}/lambdas/LogsToElasticsearch.zip"
  function_name    = "${var.prefix}-LogsToElasticsearch"
  description      = "Export logs from CloudWatch Group to Elasticsearch"
  role             = "${aws_iam_role.lambda-es-role.arn}"
  handler          = "index.handler"
  runtime          = "nodejs10.x"
  timeout          = "3"
  memory_size      = "128"
  
  depends_on    = ["aws_cloudwatch_log_group.cloudwatch_log_group"]
  
  environment {
    variables = {
      endpoint = "${aws_elasticsearch_domain.elasticsearch-domain.endpoint}"
    }
  }
}


