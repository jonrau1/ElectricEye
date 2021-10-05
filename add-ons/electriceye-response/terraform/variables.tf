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
variable "Cross_Account_Lambda_Role_Name" {
  default = "X-Acct-ElectricEye-Response-Remediation-Role"
}
variable "AWS_REGION" {
  default = "us-east-1"
}
variable "Disable_Expired_Access_Key_Playbook_XAcct_Function_Name" {
  default = "XAcct-Disable-Expired-Access-Key-Playbook"
}
variable "IAM_CIS_PW_Policy_Playbook_XAcct_Function_Name" {
  default = "XAcct-CIS-PW-Policy-Playbook"
}
variable "CloudTrail_FileValidation_Playbook_XAcct_Function_Name" {
  default = "XAcct-CloudTrail-File-Validation-Playbook"
}
variable "S3_PrivateACL_Playbook_XAcct_Function_Name" {
  default = "XAcct-Private-S3-ACL-Playbook"
}
variable "KMS_CMK_Rotation_Playbook_XAcct_Function_Name" {
  default = "XAcct-KMS-CMK-Rotation-Playbook"
}
variable "Remove_Open_SSH_Playbook_XAcct_Function_Name" {
  default = "XAcct-Remove-Open-SSH-Playbook"
}
variable "Remove_Open_RDP_Playbook_XAcct_Function_Name" {
  default = "XAcct-Remove-Open-RDP-Playbook"
}
variable "Remove_All_SG_Rules_Playbook_XAcct_Function_Name" {
  default = "XAcct-Remove-All-SG-Rules-Playbook"
}
variable "S3_Encryption_Playbook_XAcct_Function_Name" {
  default = "XAcct-S3-Encryption-Playbook"
}
variable "RDS_Privatize_Snapshot_Playbook_XAcct_Function_Name" {
  default = "XAcct-Privatize-RDS-Snapshot-Playbook"
}
variable "EBS_Privatize_Snapshot_Playbook_XAcct_Function_Name" {
  default = "XAcct-Privatize-EBS-Snapshot-Playbook"
}
variable "RDS_Privatize_Instance_Playbook_XAcct_Function_Name" {
  default = "XAcct-Privatize-RDS-Instance-Playbook"
}
variable "Redshift_Privatize_Playbook_XAcct_Function_Name" {
  default = "XAcct-Privatize-Redshift-Cluster-Playbook"
}
variable "Release_SG_Playbook_XAcct_Function_Name" {
  default = "XAcct-Release-SG-Playbook"
}
variable "Release_EIP_Playbook_XAcct_Function_Name" {
  default = "XAcct-Release-EIP-Playbook"
}
variable "SSM_ApplyPatch_Playbook_XAcct_Function_Name" {
  default = "XAcct-ApplyPatch-Playbook"
}
variable "DocDB_Privatize_Snapshot_Playbook_XAcct_Function_Name" {
  default = "XAcct-DocDb-Private-Snapshot-Playbook"
}
variable "S3_Put_Lifecycle_Playbook_XAcct_Function_Name" {
  default = "XAcct-S3-Lifecycle-Playbook"
}