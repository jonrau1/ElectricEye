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