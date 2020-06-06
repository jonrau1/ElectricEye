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

import boto3
import datetime
import os
from dateutil import parser
from auditors.Auditor import Auditor


class FunctionUnusedCheck(Auditor):
    lambda_client = boto3.client("lambda")
    cloudwatch = boto3.client("cloudwatch")
    sts = boto3.client("sts")

    def execute(self):
        response = self.lambda_client.list_functions()
        functions = response["Functions"]
        # create env vars
        awsAccountId = self.sts.get_caller_identity()["Account"]
        awsRegion = os.environ["AWS_REGION"]
        for function in functions:
            functionName = str(function["FunctionName"])
            lambdaArn = str(function["FunctionArn"])
            metricResponse = self.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": "Invocations",
                                "Dimensions": [{"Name": "FunctionName", "Value": functionName},],
                            },
                            "Period": 300,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=datetime.datetime.now() - datetime.timedelta(days=30),
                EndTime=datetime.datetime.now(),
            )
            metrics = metricResponse["MetricDataResults"]
            for metric in metrics:
                modify_date = parser.parse(function["LastModified"])
                date_delta = datetime.datetime.now(datetime.timezone.utc) - modify_date
                iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
                print(f"delta = {date_delta.days}")
                if len(metric["Values"]) > 0 or date_delta.days < 30:
                    try:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": lambdaArn + "/lambda-function-unused-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
                            "GeneratorId": lambdaArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[Lambda.1] Lambda functions should be deleted after 30 days of no use",
                            "Description": "Lambda function "
                            + functionName
                            + " has been used or updated in the last 30 days.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLambda",
                                    "Id": lambdaArn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                    except Exception as e:
                        print(e)
                else:
                    try:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": lambdaArn + "/lambda-function-unused-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
                            "GeneratorId": lambdaArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[Lambda.1] Lambda functions should be deleted after 30 days of no use",
                            "Description": "Lambda function "
                            + functionName
                            + " has not been used or updated in the last 30 days.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLambda",
                                    "Id": lambdaArn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.AM-2",
                                    "NIST SP 800-53 CM-8",
                                    "NIST SP 800-53 PM-5",
                                    "AICPA TSC CC3.2",
                                    "AICPA TSC CC6.1",
                                    "ISO 27001:2013 A.8.1.1",
                                    "ISO 27001:2013 A.8.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    except Exception as e:
                        print(e)
