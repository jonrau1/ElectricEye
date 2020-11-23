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
resource "aws_lambda_function" "ElectricEye_Pagerduty_Lambda_Function" {
  filename      = "./lambda_function.zip"
  function_name = "ElectricEye-Pagerduty"
  description   = "Sends the results of high-severity ElectricEye findings to Pagerduty as incidents - Managed by Terraform"
  role          = "${aws_iam_role.ElectricEye_Pagerduty_Lambda_Role.arn}"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 61
  environment {
    variables = {
      PAGERDUTY_INTEGRATION_KEY_PARAMETER = "${var.Pagerduty_Integration_Key_Parameter}"
    }
  }
}
resource "aws_iam_role" "ElectricEye_Pagerduty_Lambda_Role" {
  name = "electriceye-Pagerduty-lambda-role"
  description = "Sends the results of high-severity ElectricEye findings to Pagerduty as incidents - Managed by Terraform"
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
resource "aws_iam_policy" "ElectricEye_Pagerduty_Lambda_Role_Policy" {
  name = "electriceye-Pagerduty-lambda-policy"
  path = "/"
  description = "Policy for ElectricEye-Pagerduty role - Managed by Terraform"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [ 
              "kms:Decrypt",
              "ssm:GetParameter",
              "ssm:GetParameters"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
resource "aws_iam_role_policy_attachment" "SSM_Pagerduty_Policy_Attachment" {
  role = "${aws_iam_role.ElectricEye_Pagerduty_Lambda_Role.name}"
  policy_arn = "${aws_iam_policy.ElectricEye_Pagerduty_Lambda_Role_Policy.arn}"
}
resource "aws_iam_role_policy_attachment" "Lambda_Basic_Exec_Policy_Attachment" {
  role = "${aws_iam_role.ElectricEye_Pagerduty_Lambda_Role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
resource "aws_cloudwatch_event_rule" "ElectricEye_Pagerduty_Event_Rule" {
  name        = "ElectricEye-Pagerduty-CWE"
  description = "Sends the results of high-severity ElectricEye findings to Pagerduty as incidents - Managed by Terraform"
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
            "ProductFields": {
                "Product Name": [
                    "ElectricEye"
                ]
            },
            "Severity": {
                "Label": [
                    "HIGH",
                    "CRITICAL"
                ]
            }
        }
    }
}
PATTERN
}
resource "aws_cloudwatch_event_target" "ElectricEye_Pagerduty_Event_Rule_Lambda_Target" {
  rule      = "${aws_cloudwatch_event_rule.ElectricEye_Pagerduty_Event_Rule.name}"
  arn       = "${aws_lambda_function.ElectricEye_Pagerduty_Lambda_Function.arn}"
}
resource "aws_lambda_permission" "ElectricEye_Pagerduty_CWE_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.ElectricEye_Pagerduty_Lambda_Function.function_name}"
  principal     = "events.amazonaws.com"
  source_arn    = "${aws_cloudwatch_event_rule.ElectricEye_Pagerduty_Event_Rule.arn}"
}