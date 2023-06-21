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
import base64
import json

registry = CheckRegister()

def get_cloudwatch_log_groups(cache, session):
    response = cache.get("get_cloudwatch_log_groups")
    
    if response:
        return response
    
    cwlog = session.client("logs")

    logGroups = []
    for page in cwlog.get_paginator("describe_log_groups").paginate(includeLinkedAccounts=True):
        for log in page["logGroups"]:
            logGroups.append(log)

    cache["get_cloudwatch_log_groups"] = logGroups
    return cache["get_cloudwatch_log_groups"]

@registry.register_check("kms")
def aws_cloudwatch_logs_group_kms_cmk_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudWatch.1] Amazon CloudWatch Logs groups should be encrypted by an AWS Key Management Service (KMS) Customer-Managed Key (CMK)"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for group in get_cloudwatch_log_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(group,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        logGroupName = group["logGroupName"]
        logGroupArn = group["arn"]
        storedBytes = group["storedBytes"]
        # this is a failing check
        if "kmsKeyId" not in group:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-kms-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-kms-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudWatch.1] Amazon CloudWatch Logs groups should be encrypted by an AWS Key Management Service (KMS) Customer-Managed Key (CMK)",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} is not encrypted by an AWS Key Management Service (KMS) Customer-Managed Key (CMK). Log group data is always encrypted in CloudWatch Logs. By default, CloudWatch Logs uses server-side encryption for the log data at rest. As an alternative, you can use AWS Key Management Service for this encryption. If you do, the encryption is done using an AWS KMS customer managed key. Encryption using AWS KMS is enabled at the log group level, by associating a key with a log group, either when you create the log group or after it exists. After you associate a customer managed key with a log group, all newly ingested data for the log group is encrypted using this key. This data is stored in encrypted format throughout its retention period. CloudWatch Logs decrypts this data whenever it is requested. CloudWatch Logs must have permissions for the customer managed key whenever encrypted data is requested. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling AWS KMS CMK encryption for CloudWatch Logs groups refer to the Encrypt log data in CloudWatch Logs using AWS Key Management Service section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-kms-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-kms-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudWatch.1] Amazon CloudWatch Logs groups should be encrypted by an AWS Key Management Service (KMS) Customer-Managed Key (CMK)",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} is encrypted by an AWS Key Management Service (KMS) Customer-Managed Key (CMK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling AWS KMS CMK encryption for CloudWatch Logs groups refer to the Encrypt log data in CloudWatch Logs using AWS Key Management Service section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("kms")
def aws_cloudwatch_logs_group_retention_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudWatch.2] Amazon CloudWatch Logs groups should define a retention period"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for group in get_cloudwatch_log_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(group,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        logGroupName = group["logGroupName"]
        logGroupArn = group["arn"]
        storedBytes = group["storedBytes"]
        # this is a failing check
        if "retentionInDays" not in group:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-retention-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-retention-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudWatch.2] Amazon CloudWatch Logs groups should define a retention period",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} does not define a retention period. Retention settings can be used to specify how long log events are kept in CloudWatch Logs. Expired log events get deleted automatically. Just like metric filters, retention settings are also assigned to log groups, and the retention assigned to a log group is applied to their log streams. By default, log data is stored in CloudWatch Logs indefinitely. However, you can configure how long to store log data in a log group. Any data older than the current retention setting is deleted. You can change the log retention for each log group at any time. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on retention settings for CloudWatch Logs groups refer to the Change log data retention in CloudWatch Logs section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-retention-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-retention-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudWatch.2] Amazon CloudWatch Logs groups should define a retention period",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} does define a retention period.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on retention settings for CloudWatch Logs groups refer to the Change log data retention in CloudWatch Logs section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html#SettingLogRetention"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("kms")
def aws_cloudwatch_logs_group_data_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudWatch.3] Amazon CloudWatch Logs groups should be associated with a data protection policy to minimize potential sensitive information captured in logs"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for group in get_cloudwatch_log_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(group,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        logGroupName = group["logGroupName"]
        logGroupArn = group["arn"]
        storedBytes = group["storedBytes"]
        # this is a failing check
        if "retentionInDays" not in group:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-data-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-data-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudWatch.3] Amazon CloudWatch Logs groups should be associated with a data protection policy to minimize potential sensitive information captured in logs",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} is not associated with a data protection policy. You can help safeguard sensitive data that's ingested by CloudWatch Logs by using log group data protection policies. These policies let you audit and mask sensitive data that appears in log events ingested by the log groups in your account. When you create a data protection policy, then by default, sensitive data that matches the data identifiers you've selected is masked. Only users who have the logs:Unmask IAM permission can view unmasked data. Sensitive data is detected and masked when it is ingested into the log group. When you set a data protection policy, log events ingested to the log group before that time are not masked. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data protection for CloudWatch Logs groups refer to the Help protect sensitive log data with masking section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{logGroupArn}/amazon-cloudwatch-logs-data-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{logGroupArn}/amazon-cloudwatch-logs-data-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudWatch.3] Amazon CloudWatch Logs groups should be associated with a data protection policy to minimize potential sensitive information captured in logs",
                "Description": f"Amazon CloudWatch Logs group {logGroupName} is associated with a data protection policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on data protection for CloudWatch Logs groups refer to the Help protect sensitive log data with masking section of the Amazon CloudWatch Logs User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Amazon CloudWatch",
                    "AssetComponent": "Log Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudWatchLogsGroup",
                        "Id": logGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "LogGroupName": logGroupName,
                                "StoredBytes": str(storedBytes)
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??