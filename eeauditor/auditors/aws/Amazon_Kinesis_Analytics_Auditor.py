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

import datetime
import uuid
from check_register import CheckRegister, accumulate_paged_results
import base64
import json

registry = CheckRegister()

@registry.register_check("kinesisanalytics")
def kda_log_to_cloudwatch_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KinesisAnalytics.1] Applications should log to CloudWatch"""
    kinesisanalyticsv2 = session.client("kinesisanalyticsv2")

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
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(applicationDescription,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        cwDescription = applicationDescription["ApplicationDetail"][
            "CloudWatchLoggingOptionDescriptions"
        ]
        applicationArn = applicationDescription["ApplicationDetail"]["ApplicationARN"]
        generatorUuid = str(uuid.uuid4())
        if not cwDescription:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{applicationArn}/kda-log-to-cloudwatch-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Kinesis Data Analytics",
                    "AssetComponent": "Application"
                },
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
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
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
                "Id": f"{applicationArn}/kda-log-to-cloudwatch-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Kinesis Data Analytics",
                    "AssetComponent": "Application"
                },
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
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding