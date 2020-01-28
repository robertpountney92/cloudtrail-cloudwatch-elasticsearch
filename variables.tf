# Global vars
variable "prefix" {
  description = "Prefix to be applied to created resources, allowing for easy identification"
}
variable "region" {}

# Elasticsearch Vars
variable "es_version" {
  default = 5.1
}
variable "es_management_public_ip_address" {}
variable "es_instance_type" {
  default = "t2.small.elasticsearch"
}   
variable "es_instance_count" {
  default = 1
}   






