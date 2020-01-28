output "cloudtrail_name" {
    value = "${aws_cloudtrail.cloudtrail.name}"
}
output "cloudtrail_arn" {
    value = "${aws_cloudtrail.cloudtrail.arn}"
}

output "cloudtrail_s3_bucket_name" {
    value = "${aws_s3_bucket.cloudtrail_log_bucket.id}"
}
output "cloudtrail_s3_bucket_arn" {
    value = "${aws_s3_bucket.cloudtrail_log_bucket.arn}"
}


output "cloudwatch_log_group_name" {
    value = "${aws_cloudwatch_log_group.cloudwatch_log_group.name}"
}
output "cloudwatch_log_group_arn" {
    value = "${aws_cloudwatch_log_group.cloudwatch_log_group.arn}"
}

output "lambda_function_name" {
    value = "${aws_lambda_function.LogsToElasticsearch.function_name}"
}
output "lambda_function_arn" {
    value = "${aws_lambda_function.LogsToElasticsearch.arn}"
}

output "es_domain" {
    value = "${aws_elasticsearch_domain.elasticsearch-domain.domain_name}"
}
output "es_endpoint" {
    value = "${aws_elasticsearch_domain.elasticsearch-domain.endpoint}"
}
output "kibana_endpoint" {
    value = "${aws_elasticsearch_domain.elasticsearch-domain.kibana_endpoint}"
}