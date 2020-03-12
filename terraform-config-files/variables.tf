# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.  
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

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
variable "Shodan_API_Key_SSM_Parameter" {
  default =     "placeholder" # you should change me
  description = "The SSM Secure String Parameter containing your Shodan API key. Leave the default value if you will not be using Shodan"
}
variable "Electric_Eye_Schedule_Task_Expression" {
  default = "rate(12 hours)"
}