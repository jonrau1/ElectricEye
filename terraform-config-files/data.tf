data "aws_caller_identity" "current" {}
data "aws_availability_zones" "Available_AZ" {
  state = "available"
}
data "aws_iam_policy" "AWS_Managed_ECS_Events_Role" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceEventsRole"
}