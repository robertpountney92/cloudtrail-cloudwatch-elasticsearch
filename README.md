# cloudtrail-cloudwatch-elasticsearch module

Terraform module to collect and display CloudTrail logs through AWS Elasticsearch


## Usage

```hcl
module "cloudtrail-cloudwatch-elasticsearch" {
  source                            = "git::https://github.com/robertpountney92/cloudtrail-cloudwatch-elasticsearch.git?ref=master"
  prefix                            = "cce1"
  region                            = "eu-west-1"
  es_version                        = "5.1"
  es_management_public_ip_addresses = "129.XX.XXX.197"
  es_instance_type                  = "t2.small.elasticsearch"
  es_instance_count                 = "1"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| prefix | Prefix to be applied to created resources, allowing for easy identification of those resources | string | `` | yes |
| region| AWS region | string | `` | yes |
| es_version | Elasticsearch version | string | 5.1 | no |
| es_management_public_ip_addresses | IP addresses permitted to access the Elasticsearch domain | string | [] | yes |
| es_instance_type | The instance type for instances within Elasticsearch cluster | string | `t2.small.elasticsearch` | no |
| es_instance_count | Number of instances in Elasticsearch cluster | number | 1 | no |

## Outputs

| Name | Description |
|------|-------------|
| cloudtrail_name | CloudTrail Name |
| cloudtrail_arn | CloudTrail ARN |
| cloudtrail_s3_bucket_name | Name of S3 bucket used to store CloudTrail Logs |
| cloudtrail_s3_bucket_arn | ARN of S3 bucket used to store CloudTrail Logs |
| cloudwatch_log_group_name | CloudWatch Log group name |
| cloudtrail_log_group_arn | CloudWatch Log group ARN |
| lambda_function_name | Lambda function name |
| lambda_function_arn | Lambda function ARN |
| es_domain | Elasticsearch domain name |
| es_endpoint | Elasticsearch endpoint used to submit index, search, and data upload requests |
| kibana_endpoint | Kibana endpoint for accessing dashboards |


## Manual steps

When you visit the Kibana endpoint for the first time you will be prompted to configure an index pattern where you have to

    Turn on "Index contains time-based events"
    Turn on "Use event times to create index names"
    Pick "Daily" for the "Index pattern interval" field
    Enter [cwl-]YYYY.MM.DD for the "Index name or pattern" field
    Choose @timestamp for the "Time-field name"
