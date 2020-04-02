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
variable "AWS_REGION" {
  default = "us-east-1"
}
variable "Python3_Requests_Layer_ARN" {
  default     = "arn:aws:lambda:us-east-1:770693421928:layer:Klayers-python38-requests:3"
  description = "The regional ARN with Version of the Lambda Layer that has Python 3 support for the requests library"
}
variable "Teams_Webhook_Parameter" {
  default     = ""
  description = "The name of the SSM Parameter that contains the Teams App Webhook URL for ElectricEye-ChatOps"
}