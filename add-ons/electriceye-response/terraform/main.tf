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
resource "aws_iam_role" "Security_Hub_XAcct_Lambda_Role" {
  name = "${var.Cross_Account_Lambda_Role_Name}"
  description = "Role for ElectricEye full automatic cross-account response and remediation playbooks - Managed by Terraform"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_policy" "Security_Hub_XAcct_Lambda_Role_Policy" {
  name = "${var.Cross_Account_Lambda_Role_Name}-policy"
  path = "/"
  description = "Policy for ElectricEye full automatic cross-account response and remediation playbooks - Managed by Terraform"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
              "cloudtrail:UpdateTrail",
              "ec2:DescribeSecurityGroups",
              "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
              "ec2:RevokeSecurityGroupIngress",
              "ec2:DescribeSecurityGroupReferences",
              "ec2:ReleaseAddress",
              "ec2:ModifySnapshotAttribute",
              "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
              "ec2:RevokeSecurityGroupEgress",
              "ec2:DeleteSecurityGroup",
              "ec2:DescribeInstances",
              "ec2:RevokeSecurityGroupEgress",
              "ec2:ModifyInstanceAttribute",
              "ec2:EnableEbsEncryptionByDefault",
              "iam:UpdateAccessKey",
              "iam:ListAccessKeys",
              "iam:PassRole",
              "iam:UpdateAccountPasswordPolicy",
              "kms:EnableKeyRotation",
              "securityhub:UpdateFindings",
              "s3:PutBucketAcl",
              "s3:PutEncryptionConfiguration",
              "s3:PutBucketPublicAccessBlock",
              "ssm:SendCommand",
              "ssm:StartAutomationExecution",
              "ssm:GetParameter",
              "ssm:GetParameters",
              "sts:AssumeRole",
              "rds:ModifyDBCluster",
              "rds:ModifyDBClusterSnapshotAttribute",
              "rds:ModifyDBSnapshot",
              "rds:ModifyDBInstance",
              "rds:ModifyDBSnapshotAttribute",
              "redshift:ModifyCluster"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "XAcct_Remediation_Policy_Attachment" {
  role = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.name}"
  policy_arn = "${aws_iam_policy.Security_Hub_XAcct_Lambda_Role_Policy.arn}"
}
resource "aws_iam_role_policy_attachment" "Lambda_Basic_Exec_Policy_Attachment" {
  role = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
resource "aws_iam_role_policy_attachment" "AWS_Backup_Backups_Policy_Attachment" {
  role = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}
resource "aws_iam_role_policy_attachment" "SSM_Automation_Policy_Attachment" {
  role = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSSMAutomationRole"
}
resource "aws_cloudwatch_event_rule" "Deactivate_Old_Access_Key_Event_Rule" {
  name        = "x-acct-deactivate-access-key-rule"
  description = "After execution will look for IAM access keys over 90 days old and deactivate them - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsIamUser"
        ]
      },
      "Title": [
        "1.3 Ensure credentials unused for 90 days or greater are disabled",
        "1.4 Ensure access keys are rotated every 90 days or less"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Deactivate_Old_Access_Key_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Deactivate_Old_Access_Key_Event_Rule.name}"
  arn       = "${aws_lambda_function.Deactivate_Old_Access_Key_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Deactivate_Old_Access_Key_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Deactivate_Old_Access_Key_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Deactivate_Old_Access_Key_Event_Rule.arn}"
}
resource "aws_lambda_function" "Deactivate_Old_Access_Key_XAcct_Function" {
  filename      = "./Disable_Expired_Access_Key_Playbook.zip"
  function_name = "${var.Disable_Expired_Access_Key_Playbook_XAcct_Function_Name}"
  description   = "After execution will look for IAM access keys over 90 days old and deactivate them - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Disable_Expired_Access_Key_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "IAM_CIS_PW_Policy_Playbook_Event_Rule" {
  name        = "x-acct-apply-str-pw-policy-rule"
  description = "After execution will apply all factors of a strong IAM password policy according to the AWS CIS Foundations Benchmark - Manged by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Title": [
        "1.5 Ensure IAM password policy requires at least one uppercase letter",
        "1.6 Ensure IAM password policy requires at least one lowercase letter",
        "1.7 Ensure IAM password policy requires at least one symbol",
        "1.8 Ensure IAM password policy requires at least one number",
        "1.9 Ensure IAM password policy requires minimum password length of 14 or greater",
        "1.10 Ensure IAM password policy prevents password reuse",
        "1.11 Ensure IAM password policy expires passwords within 90 days or less"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "IAM_CIS_PW_Policy_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.IAM_CIS_PW_Policy_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.IAM_CIS_PW_Policy_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "IAM_CIS_PW_Policy_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.IAM_CIS_PW_Policy_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.IAM_CIS_PW_Policy_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "IAM_CIS_PW_Policy_Playbook_XAcct_Function" {
  filename      = "./IAM_CIS_PW_Policy_Playbook.zip"
  function_name = "${var.IAM_CIS_PW_Policy_Playbook_XAcct_Function_Name}"
  description   = "After execution will apply all factors of a strong IAM password policy according to the AWS CIS Foundations Benchmark - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "IAM_CIS_PW_Policy_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "CloudTrail_FileValidation_Playbook_Event_Rule" {
  name        = "x-acct-ct-log-validaiton-rule"
  description = "After execution will re-enable CloudTrail log file validation - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsCloudTrailTrail"
        ]
      },
      "Title": [
        "2.2 Ensure CloudTrail log file validation is enabled (Scored)",
        "PCI.CloudTrail.3 CloudTrail log file validation should be enabled"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "CloudTrail_FileValidation_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.CloudTrail_FileValidation_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.CloudTrail_FileValidation_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "CloudTrail_FileValidation_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.CloudTrail_FileValidation_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.CloudTrail_FileValidation_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "CloudTrail_FileValidation_Playbook_XAcct_Function" {
  filename      = "./CloudTrail_FileValidation_Playbook.zip"
  function_name = "${var.CloudTrail_FileValidation_Playbook_XAcct_Function_Name}"
  description   = "After execution will re-enable CloudTrail log file validation - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "CloudTrail_FileValidation_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "S3_PrivateACL_Playbook_Event_Rule" {
  name        = "x-acct-apply-priv-s3-acl-rule"
  description = "After execution will apply a private ACL to a public bucket - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsS3Bucket"
        ]
      },
      "Title": [
        "2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Scored)",
        "PCI.S3.1 S3 bucket should prohibit public write access",
        "PCI.S3.2 S3 bucket should prohibit public read access"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "S3_PrivateACL_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.S3_PrivateACL_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.S3_PrivateACL_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "S3_PrivateACL_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.S3_PrivateACL_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.S3_PrivateACL_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "S3_PrivateACL_Playbook_XAcct_Function" {
  filename      = "./S3_PrivateACL_Playbook.zip"
  function_name = "${var.S3_PrivateACL_Playbook_XAcct_Function_Name}"
  description   = "Remediates CIS 2.3 by placing private bucket ACL on CloudTrail log bucket - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "S3_PrivateACL_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "KMS_CMK_Rotation_Playbook_Event_Rule" {
  name        = "x-acct-enable-cmk-rotation-rule"
  description = "Afte exeuction will enable rotation on KMS CMKs without it. This will fail on keys scheduled for deletion - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsKmsKey"
        ]
      },
      "Title": [
        "2.8 Ensure rotation for customer created CMKs is enabled",
        "PCI.KMS.1 Customer master key (CMK) rotation should be enabled"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "KMS_CMK_Rotation_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.KMS_CMK_Rotation_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.KMS_CMK_Rotation_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "KMS_CMK_Rotation_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.KMS_CMK_Rotation_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.KMS_CMK_Rotation_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "KMS_CMK_Rotation_Playbook_XAcct_Function" {
  filename      = "./KMS_CMK_Rotation_Playbook.zip"
  function_name = "${var.KMS_CMK_Rotation_Playbook_XAcct_Function_Name}"
  description   = "Remediates CIS 2.8 by enabling key rotation for KMS CMKs - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "KMS_CMK_Rotation_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Remove_Open_SSH_Playbook_Event_Rule" {
  name        = "x-acct-remove-ssh-rule"
  description = "After execution will remove Security Group rules allowing SSH access to 0.0.0.0/0 - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2SecurityGroup"
        ]
      },
      "Title": [
        "4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Remove_Open_SSH_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Remove_Open_SSH_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Remove_Open_SSH_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Remove_Open_SSH_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Remove_Open_SSH_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Remove_Open_SSH_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Remove_Open_SSH_Playbook_XAcct_Function" {
  filename      = "./Remove_Open_SSH_Playbook.zip"
  function_name = "${var.Remove_Open_SSH_Playbook_XAcct_Function_Name}"
  description   = "After execution will remove Security Group rules allowing SSH access to 0.0.0.0/0 - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Remove_Open_SSH_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Remove_Open_RDP_Playbook_Event_Rule" {
  name        = "x-acct-remove-rdp-rule"
  description = "After execution will remove Security Group rules allowing RDP access to 0.0.0.0/0 - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2SecurityGroup"
        ]
      },
      "Title": [
        "4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Remove_Open_RDP_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Remove_Open_RDP_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Remove_Open_RDP_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Remove_Open_RDP_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Remove_Open_RDP_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Remove_Open_RDP_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Remove_Open_RDP_Playbook_XAcct_Function" {
  filename      = "./Remove_Open_RDP_Playbook.zip"
  function_name = "${var.Remove_Open_RDP_Playbook_XAcct_Function_Name}"
  description   = "After execution will remove Security Group rules allowing RDP access to 0.0.0.0/0 - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Remove_Open_RDP_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Remove_All_SG_Rules_Playbook_Event_Rule" {
  name        = "x-acct-remove-default-sg-rules-rule"
  description = "After exeuction will remove all ingress and egress rules for the targetted security group - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2SecurityGroup"
        ]
      },
      "Title": [
        "4.3 Ensure the default security group of every VPC restricts all traffic",
        "PCI.EC2.2 VPC default security group should prohibit inbound and outbound traffic"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Remove_All_SG_Rules_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Remove_All_SG_Rules_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Remove_All_SG_Rules_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Remove_All_SG_Rules_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Remove_All_SG_Rules_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Remove_All_SG_Rules_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Remove_All_SG_Rules_Playbook_XAcct_Function" {
  filename      = "./Remove_All_SG_Rules_Playbook.zip"
  function_name = "${var.Remove_All_SG_Rules_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove all ingress and egress rules for the target security group - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Remove_All_SG_Rules_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "S3_Encryption_Playbook_Event_Rule" {
  name        = "x-acct-s3-encryption-rule"
  description = "After exeuction will apply SSE-S3 to your bucket - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsS3Bucket"
        ]
      },
      "Title": [
        "PCI.S3.4 S3 buckets should have server-side encryption enabled"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "S3_Encryption_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.S3_Encryption_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.S3_Encryption_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "S3_Encryption_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.S3_Encryption_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.S3_Encryption_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "S3_Encryption_Playbook_XAcct_Function" {
  filename      = "./S3_Encryption_Playbook.zip"
  function_name = "${var.S3_Encryption_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will apply SSE-S3 to your bucket - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "S3_Encryption_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "RDS_Privatize_Snapshot_Playbook_Event_Rule" {
  name        = "x-acct-private-rds-snapshot-rule"
  description = "After exeuction will remove all public access to the RDS snapshot - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsRdsDBSnapshot"
        ]
      },
      "Title": [
        "PCI.RDS.1 RDS snapshots should prohibit public access"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "RDS_Privatize_Snapshot_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.RDS_Privatize_Snapshot_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.RDS_Privatize_Snapshot_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "RDS_Privatize_Snapshot_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.RDS_Privatize_Snapshot_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.RDS_Privatize_Snapshot_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "RDS_Privatize_Snapshot_Playbook_XAcct_Function" {
  filename      = "./RDS_Privatize_Snapshot_Playbook.zip"
  function_name = "${var.RDS_Privatize_Snapshot_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove all public access to the RDS snapshot - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "RDS_Privatize_Snapshot_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "EBS_Privatize_Snapshot_Playbook_Event_Rule" {
  name        = "x-acct-private-ebs-snapshot-rule"
  description = "After exeuction will remove all public access to the EBS Snapshot - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2Snapshot"
        ]
      },
      "Title": [
        "PCI.EC2.1 EBS snapshots should not be publicly restorable"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "EBS_Privatize_Snapshot_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.EBS_Privatize_Snapshot_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.EBS_Privatize_Snapshot_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "EBS_Privatize_Snapshot_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.EBS_Privatize_Snapshot_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.EBS_Privatize_Snapshot_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "EBS_Privatize_Snapshot_Playbook_XAcct_Function" {
  filename      = "./EBS_Privatize_Snapshot_Playbook.zip"
  function_name = "${var.EBS_Privatize_Snapshot_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove all public access to the EBS Snapshot - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "EBS_Privatize_Snapshot_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "RDS_Privatize_Instance_Playbook_Event_Rule" {
  name        = "x-acct-private-rds-instance-rule"
  description = "After exeuction will remove public access from the RDS Instance - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsRdsDbInstance"
        ]
      },
      "Title": [
        "PCI.RDS.2 RDS DB Instances should prohibit public access"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "RDS_Privatize_Instance_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.RDS_Privatize_Instance_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.RDS_Privatize_Instance_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "RDS_Privatize_Instance_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.RDS_Privatize_Instance_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.RDS_Privatize_Instance_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "RDS_Privatize_Instance_Playbook_XAcct_Function" {
  filename      = "./RDS_Privatize_Instance_Playbook.zip"
  function_name = "${var.RDS_Privatize_Instance_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove public access from the RDS Instance - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "RDS_Privatize_Instance_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Redshift_Privatize_Playbook_Event_Rule" {
  name        = "x-acct-private-rshift-cluster-rule"
  description = "After exeuction will remove public access from the Redshift Cluster - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsRedshiftCluster"
        ]
      },
      "Title": [
        "PCI.Redshift.1 Redshift clusters should prohibit public access"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Redshift_Privatize_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Redshift_Privatize_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Redshift_Privatize_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Redshift_Privatize_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Redshift_Privatize_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Redshift_Privatize_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Redshift_Privatize_Playbook_XAcct_Function" {
  filename      = "./Redshift_Privatize_Playbook.zip"
  function_name = "${var.Redshift_Privatize_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove public access from the Redshift Cluster - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Redshift_Privatize_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Release_SG_Playbook_Event_Rule" {
  name        = "x-acct-remove-sg-rule"
  description = "After exeuction will remove unused EC2 Security Groups - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2SecurityGroup"
        ]
      },
      "Title": [
        "PCI.EC2.3 Unused EC2 security groups should be removed"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Release_SG_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Release_SG_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Release_SG_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Release_SG_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Release_SG_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Release_SG_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Release_SG_Playbook_XAcct_Function" {
  filename      = "./Release_SG_Playbook.zip"
  function_name = "${var.Release_SG_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove unused EC2 Security Groups - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Release_SG_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "Release_EIP_Playbook_Event_Rule" {
  name        = "x-acct-remove-eip-rule"
  description = "After exeuction will remove unallocated Elastic IP addresses - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Resources": {
        "Type": [
          "AwsEc2Eip"
        ]
      },
      "Title": [
        "PCI.EC2.4 Unused EC2 EIPs should be removed"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "Release_EIP_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.Release_EIP_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.Release_EIP_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "Release_EIP_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Release_EIP_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.Release_EIP_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "Release_EIP_Playbook_XAcct_Function" {
  filename      = "./Release_EIP_Playbook.zip"
  function_name = "${var.Release_EIP_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove unallocated Elastic IP addresses - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "Release_EIP_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "SSM_ApplyPatch_Playbook_Event_Rule" {
  name        = "x-acct-update-ssm-patch-rule"
  description = "After exeuction will invoke a SSM Command Document to apply security patches to an instance - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "Resources": {
        "Type": [
          "AwsSsmPatchCompliance"
        ]
      },
    "findings": {
      "Title": [
        "PCI.SSM.1 EC2 instances managed by Systems Manager should have a patch compliance status of COMPLIANT after a patch installation"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "SSM_ApplyPatch_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.SSM_ApplyPatch_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.SSM_ApplyPatch_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "SSM_ApplyPatch_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.SSM_ApplyPatch_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.SSM_ApplyPatch_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "SSM_ApplyPatch_Playbook_XAcct_Function" {
  filename      = "./PCI_Edition_SSM_ApplyPatch_Playbook.zip"
  function_name = "${var.SSM_ApplyPatch_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will invoke a SSM Command Document to apply security patches to an instance - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "PCI_Edition_SSM_ApplyPatch_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "DocDB_Privatize_Snapshot_Playbook_Event_Rule" {
  name        = "x-acct-privatize-docdb-snapshot-rule"
  description = "After exeuction will remove public access to the DocDB Cluster snapshot - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Title": [
        "[DocDb.9] DocumentDB cluster snapshots should not be publicly shared"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "DocDB_Privatize_Snapshot_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.DocDB_Privatize_Snapshot_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.DocDB_Privatize_Snapshot_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "DocDB_Privatize_Snapshot_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.DocDB_Privatize_Snapshot_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.DocDB_Privatize_Snapshot_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "DocDB_Privatize_Snapshot_Playbook_XAcct_Function" {
  filename      = "./DocDB_Privatize_Snapshot_Playbook.zip"
  function_name = "${var.DocDB_Privatize_Snapshot_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will remove public access to the DocDB Cluster snapshot - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "DocDB_Privatize_Snapshot_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}
resource "aws_cloudwatch_event_rule" "S3_Put_Lifecycle_Playbook_Event_Rule" {
  name        = "x-acct-s3-lifecycle-rule"
  description = "After exeuction will apply a basic lifecycle configuration policy on an S3 bucket to move old files to cheaper storage - Managed by Terraform"
  event_pattern = <<PATTERN
	{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
    "findings": {
      "Title": [
        "[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations"
      ],
      "Compliance": {
        "Status": [
          "FAILED"
        ]
      }
    }
  }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "S3_Put_Lifecycle_Playbook_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.S3_Put_Lifecycle_Playbook_Event_Rule.name}"
  arn       = "${aws_lambda_function.S3_Put_Lifecycle_Playbook_XAcct_Function.arn}"
}
resource "aws_lambda_permission" "S3_Put_Lifecycle_Playbook_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.S3_Put_Lifecycle_Playbook_XAcct_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.S3_Put_Lifecycle_Playbook_Event_Rule.arn}"
}
resource "aws_lambda_function" "S3_Put_Lifecycle_Playbook_XAcct_Function" {
  filename      = "./S3_Put_Lifecycle_Playbook.zip"
  function_name = "${var.S3_Put_Lifecycle_Playbook_XAcct_Function_Name}"
  description   = "After exeuction will apply a basic lifecycle configuration policy on an S3 bucket to move old files to cheaper storage - Managed by Terraform"
  role          = "${aws_iam_role.Security_Hub_XAcct_Lambda_Role.arn}"
  handler       = "S3_Put_Lifecycle_Playbook.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 181
}