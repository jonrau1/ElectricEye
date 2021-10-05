#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.

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
variable "Electric_Eye_ECR_Repository_Name" {
  default     = ""
  description = "ECR Repo name for ElectricEye this will be used to place a resource policy allowing access from only the ElectricEye roles"
}
variable "Electric_Eye_Docker_Image_URI" {
  default     = ""
  description = "URI of the ElectricEye Docker image from ECR" 
}
variable "Shodan_API_Key_SSM_Parameter" {
  default =     "placeholder"
  description = "The SSM Secure String Parameter containing your Shodan API key. Leave the default value if you will not be using Shodan"
}
variable "Dops_client_id_SSM_Parameter" {
  default =     "placeholder"
  description = "The SSM Secure String Parameter containing your DisruptOps client id. Leave the default value if you will not be using DisruptOps"
}
variable "Dops_api_key_SSM_Parameter" {
  default =     "placeholder"
  description = "The SSM Secure String Parameter containing your DisruptOps API key. Leave the default value if you will not be using DisruptOps"
}
# PostgreSQL
variable "postgres_username" {
  default =     "placeholder"
  description = "Main PostgreSQL User Name used for DB Authentication. Leave the default value if you will not be sending findings to PostgreSQL"
}
variable "postgres_endpoint" {
  default =     "placeholder"
  description = "Hostname of your PostgreSQL Database. Leave the default value if you will not be sending findings to PostgreSQL"
}
variable "postgres_db_name" {
  default =     "placeholder"
  description = "Database Name within PostgreSQL to place ElectricEye table. Leave the default value if you will not be using PostgreSQL"
}
variable "postgres_port" {
  default =     "placeholder"
  description = "The Port Number of your PostgreSQL Database. Leave the default value if you will not be using PostgreSQL"
}
variable "postgre_password_SSM_Parameter" {
  default =     "placeholder"
  description = "The SSM Secure String Parameter containing your PostgreSQL Password. Leave the default value if you will not be using PostgreSQL"
}
variable "Electric_Eye_Schedule_Task_Expression" {
  default = "rate(12 hours)"
}