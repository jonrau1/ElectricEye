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

import datetime
from dateutil import parser
import uuid

import boto3

from check_register import CheckRegister, accumulate_paged_results

registry = CheckRegister()
kinesisanalyticsv2 = boto3.client("kinesisanalyticsv2")


@registry.register_check("kinesisanalyticsv2")
def kda_log_to_cloudwatch_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    paginator = kinesisanalyticsv2.get_paginator("list_applications")
    response_iterator = paginator.paginate()
    responses = accumulate_paged_results(
        page_iterator=response_iterator, key="ApplicationSummaries"
    )
    applications = responses["ApplicationSummaries"]
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for application in applications:
        applicationName = application["ApplicationName"]
        applicationDescription = kinesisanalyticsv2.describe_application(
            ApplicationName=applicationName
        )
        cwDescription = applicationDescription["ApplicationDetail"][
            "CloudWatchLoggingOptionDescriptions"
        ]
        applicationArn = applicationDescription["ApplicationDetail"]["ApplicationARN"]
        generatorUuid = str(uuid.uuid4())
        if not cwDescription:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": applicationArn + "/kda-log-to-cloudwatch-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[KinesisAnalytics.1] Applications should log to CloudWatch",
                "Description": "Application "
                + applicationName
                + " does not log to CloudWatch.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on monitoring applications using CloudWatch Logs refer to the Best Practices for Kinesis Data Analytics for Apache Flink section of the Amazon Kinesis Data Analytics Developer Guide",
                        "Url": "https://docs.aws.amazon.com/kinesisanalytics/latest/java/best-practices.html#how-dev-bp-logging",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsKinesisDataAnalyticsApplication",
                        "Id": applicationArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": applicationArn + "/kda-log-to-cloudwatch-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[KinesisAnalytics.1] Applications should log to CloudWatch",
                "Description": "Application "
                + applicationName
                + " does not log to CloudWatch.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on monitoring applications using CloudWatch Logs refer to the Best Practices for Kinesis Data Analytics for Apache Flink section of the Amazon Kinesis Data Analytics Developer Guide",
                        "Url": "https://docs.aws.amazon.com/kinesisanalytics/latest/java/best-practices.html#how-dev-bp-logging",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsKinesisDataAnalyticsApplication",
                        "Id": applicationArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
