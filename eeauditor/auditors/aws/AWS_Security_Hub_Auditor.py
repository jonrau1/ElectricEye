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

from check_register import CheckRegister
import datetime
from botocore.exceptions import ClientError

registry = CheckRegister()

@registry.register_check("securityhub")
def high_critical_findings(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityHub.1] AWS Security Hub should be enabled in the current AWS region"""
    sechub = session.client("securityhub")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Default ARN, minus the "/default" namespace for the Hub
    hubArn = f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:hub"
    try:
        sechub.describe_hub()
        sechubEnabled = True
    except ClientError:
        sechubEnabled = False
    # this is a failing finding
    if sechubEnabled is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{hubArn}/security-hub-enabled-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{hubArn}/security-hub-enabled-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "FirstObservedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[SecurityHub.1] AWS Security Hub should be enabled in the current AWS region",
            "Description": f"AWS Security Hub is not enabled in the current AWS Region ({awsRegion}) for AWS Account {awsAccountId}. Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products. AWS Security Hub provides you with a comprehensive view of your security state in AWS and helps you check your environment against security industry standards and best practices - enabling you to quickly assess the security posture across your AWS accounts. It is recommended AWS Security Hub be enabled in all regions. AWS Security Hub requires AWS Config to be enabled. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling AWS Security Hub refer to the Enabling Security Hub manually section in the AWS Security Hub User Guide",
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": None,
                "AssetClass": "Security Services",
                "AssetService": "AWS Security Hub",
                "AssetComponent": "Hub"
            },
            "Resources": [
                {
                    "Type": "AwsSecurityHubHub",
                    "Id": hubArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 4.16",
                    "CIS Amazon Web Services Foundations Benchmark V2.0 4.16",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 4.16",
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{hubArn}/security-hub-enabled-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{hubArn}/security-hub-enabled-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "FirstObservedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SecurityHub.1] AWS Security Hub should be enabled in the current AWS region",
            "Description": f"AWS Security Hub is enabled in the current AWS Region ({awsRegion}) for AWS Account {awsAccountId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling AWS Security Hub refer to the Enabling Security Hub manually section in the AWS Security Hub User Guide",
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-enable.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": None,
                "AssetClass": "Security Services",
                "AssetService": "AWS Security Hub",
                "AssetComponent": "Hub"
            },
            "Resources": [
                {
                    "Type": "AwsSecurityHubHub",
                    "Id": hubArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 3.5",
                    "CIS Amazon Web Services Foundations Benchmark V2.0 3.5",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 4.16",
                    "CIS Amazon Web Services Foundations Benchmark V2.0 4.16",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 4.16",
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding