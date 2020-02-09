variable "AWS_Region" {
  default = "us-east-1"
}
variable "Electric_Eye_VPC_CIDR" {
  default = "10.66.0.0/16"
}
variable "Electric_Eye_VPC_Name_Tag" {
  default = "electric-eye-vpc"
}
variable "Network_Resource_Count" {
  default = 2
}
variable "Electric_Eye_ECS_Resources_Name" {
  default = "electriceye"
}
variable "Electric_Eye_Docker_Image_URI" {
  default     = ""
  description = "URI of the ElectricEye Docker image from ECR" 
}
variable "Electric_Eye_Schedule_Task_Expression" {
  default = "rate(12 hours)"
}