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

import logging
from check_register import CheckRegister
import datetime
import base64
import json
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

registry = CheckRegister()

def get_all_shadow_trails(cache, session):
    response = cache.get("get_all_shadow_trails")
    if response:
        return response
    
    cloudtrail = session.client("cloudtrail")

    cache["get_all_shadow_trails"] = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]
    return cache["get_all_shadow_trails"]

def check_if_bucket_is_public(session, bucketName):
    s3 = session.client("s3")

    try:
        bucketPublic = s3.get_bucket_policy_status(Bucket=bucketName)["PolicyStatus"]["IsPublic"]
    except ClientError:
        bucketPublic = False

    return bucketPublic

def check_bucket_server_access_logging(session, bucketName):
    s3 = session.client("s3")

    logging = s3.get_bucket_logging(Bucket=bucketName)
    if "LoggingEnabled" in logging:
        serverAccessLogging = True
    else:
        serverAccessLogging = False

    return serverAccessLogging

@registry.register_check("cloudtrail")
def cloudtrail_multi_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.1] AWS CloudTrail trails should be enabled in all Regions"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # this is a failing check
        if trail["IsMultiRegionTrail"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-multi-region-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-multi-region-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.1] AWS CloudTrail trails should be enabled in all Regions",
                "Description": f"AWS CloudTrail trail {trailName} is not a multi-region trail. You can configure CloudTrail to deliver log files from multiple Regions to a single S3 bucket for a single account. For example, you have a trail in the US West (Oregon) Region that is configured to deliver log files to a S3 bucket, and a CloudWatch Logs log group. When you change an existing single-Region trail to log all Regions, CloudTrail logs events from all Regions that are in a single AWS partition in your account. CloudTrail delivers log files to the same S3 bucket and CloudWatch Logs log group. As long as CloudTrail has permissions to write to an S3 bucket, the bucket for a multi-Region trail does not have to be in the trail's home Region. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-multi-region-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-multi-region-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.1] AWS CloudTrail trails should be enabled in all Regions",
                "Description": f"AWS CloudTrail trail {trailName} is a multi-region trail.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.2] AWS CloudTrail trails should have CloudWatch logging configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # this is a failing check
        if "CloudWatchLogsLogGroupArn" not in trail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.2] AWS CloudTrail trails should have CloudWatch logging configured",
                "Description": f"AWS CloudTrail trail {trailName} does not have CloudWatch Logging configured. When you configure your trail to send events to CloudWatch Logs, CloudTrail sends only the events that match your trail settings. For example, if you configure your trail to log data events only, your trail sends data events only to your CloudWatch Logs log group. CloudTrail supports sending data, Insights, and management events to CloudWatch Logs. Make sure you have sufficient permissions to create or specify an IAM role. CloudWatch Logs and EventBridge each allow a maximum event size of 256 KB. Although most service events have a maximum size of 256 KB, some services still have events that are larger. CloudTrail does not send these events to CloudWatch Logs or EventBridge. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding   
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.2] AWS CloudTrail trails should have CloudWatch logging configured",
                "Description": f"AWS CloudTrail trail {trailName} does have CloudWatch Logging configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding 

@registry.register_check("cloudtrail")
def cloudtrail_logs_kms_cmk_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.3] AWS CloudTrail trail logs should be encrypted by an AWS KMS Customer Managed Key (CMK)"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # this is a failing check
        if "KmsKeyId" not in trail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-logs-kms-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-logs-kms-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.3] AWS CloudTrail trail logs should be encrypted by an AWS KMS Customer Managed Key (CMK)",
                "Description": f"AWS CloudTrail trail {trailName} does not encrypt its logs with an AWS KMS Customer Managed Key (CMK). By default, the log files delivered by CloudTrail to your bucket are encrypted by Amazon server-side encryption with Amazon S3-managed encryption keys (SSE-S3). To provide a security layer that is directly manageable, you can instead use server-side encryption with AWS KMS keys (SSE-KMS) for your CloudTrail log files. To use SSE-KMS with CloudTrail, you create and manage a KMS key, also known as an AWS KMS key. You attach a policy to the key that determines which users can use the key for encrypting and decrypting CloudTrail log files. The decryption is seamless through S3. When authorized users of the key read CloudTrail log files, S3 manages the decryption, and the authorized users are able to read log files in unencrypted form. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS Customer Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-logs-kms-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-logs-kms-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.3] AWS CloudTrail trail logs should be encrypted by an AWS KMS Customer Managed Key (CMK)",
                "Description": f"AWS CloudTrail trail {trailName} does encrypt its logs with an AWS KMS Customer Managed Key (CMK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS Customer Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_management_event_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.4] AWS CloudTrail trails should log management events"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # this is a failing check
        if trail["IncludeGlobalServiceEvents"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-management-events-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-management-events-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudTrail.4] AWS CloudTrail trails should log management events",
                "Description": f"AWS CloudTrail trail {trailName} does not log management events. By default, trails log management events and don't include data or Insights events. Management events provide visibility into management operations that are performed on resources in your AWS account. These are also known as control plane operations. Example management events include: Configuring security (for example, IAM AttachRolePolicy API operations), Registering devices (for example, Amazon EC2 CreateDefaultVpc API operations), Configuring rules for routing data (for example, Amazon EC2 CreateSubnet API operations), and Setting up logging (for example, AWS CloudTrail CreateTrail API operations). Management events can also include non-API events that occur in your account. For example, when a user logs in to your account, CloudTrail logs the ConsoleLogin event. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-management-events-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-management-events-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.4] AWS CloudTrail trails should log management events",
                "Description": f"AWS CloudTrail trail {trailName} does log management events.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_log_file_validation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.5] AWS CloudTrail log file validation should be enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # this is a failing check
        if trail["LogFileValidationEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-log-file-validation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-log-file-validation-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.5] AWS CloudTrail log file validation should be enabled",
                "Description": f"AWS CloudTrail trail {trailName} does not enable log file validation. To determine whether a log file was modified, deleted, or unchanged after CloudTrail delivered it, you can use CloudTrail log file integrity validation. This feature is built using industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing. This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection. You can use the AWS CLI to validate the files in the location where CloudTrail delivered them. Validated log files are invaluable in security and forensic investigations. For example, a validated log file enables you to assert positively that the log file itself has not changed, or that particular user credentials performed specific API activity. The CloudTrail log file integrity validation process also lets you know if a log file has been deleted or changed, or assert positively that no log files were delivered to your account during a given period of time. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 SC-16",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-log-file-validation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-log-file-validation-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.5] AWS CloudTrail log file validation should be enabled",
                "Description": f"AWS CloudTrail trail {trailName} does enable log file validation.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 SC-16",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_bucket_public_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.6] AWS CloudTrail trail Amazon S3 logs bucket should not be publicly accessible"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        bucketName = trail["S3BucketName"]
        # Get the bucket from the trail and pass it to another function to check if it is public facing. If so, that's really fucking bad and stupid
        # first, we need to use HeadBucket to make sure it's in our Account, if not we'll skip it
        try:
            s3.head_bucket(Bucket=bucketName)
            bucketInAccount = True
        except ClientError:
            print(f"S3 Bucket {bucketName} for AWS CloudTrail trail {trailName} is not located in this Account - skipping!")
            bucketInAccount = False

        if bucketInAccount is False:
            continue
        else:
            bucketPublic = check_if_bucket_is_public(session, bucketName)

        # this is a failing check
        if bucketPublic is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-bucket-is-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-bucket-is-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.6] AWS CloudTrail trail Amazon S3 logs bucket should not be publicly accessible",
                "Description": f"AWS CloudTrail trail {trailName} Amazon S3 logs bucket is publicly accessible. Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-bucket-is-public-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-bucket-is-public-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.6] AWS CloudTrail trail Amazon S3 logs bucket should not be publicly accessible",
                "Description": f"AWS CloudTrail trail {trailName} Amazon S3 logs bucket is not publicly accessible.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_bucket_server_access_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.7] AWS CloudTrail trail Amazon S3 logs bucket should enable server access logging"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        bucketName = trail["S3BucketName"]
        # Get the bucket from the trail and pass it to another function to check if it is public facing. If so, that's really fucking bad and stupid
        # first, we need to use HeadBucket to make sure it's in our Account, if not we'll skip it
        try:
            s3.head_bucket(Bucket=bucketName)
            bucketInAccount = True
        except ClientError:
            print(f"S3 Bucket {bucketName} for AWS CloudTrail trail {trailName} is not located in this Account - skipping!")
            bucketInAccount = False

        if bucketInAccount is False:
            continue
        else:
            serverAccessLogging = check_bucket_server_access_logging(session, bucketName)

        # this is a failing check
        if serverAccessLogging is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-bucket-server-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-bucket-server-access-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.7] AWS CloudTrail trail Amazon S3 logs bucket should enable server access logging",
                "Description": f"AWS CloudTrail trail {trailName} Amazon S3 logs bucket does not enable server access logging. By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Amazon S3 Server Access Logging section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-bucket-server-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-bucket-server-access-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.7] AWS CloudTrail trail Amazon S3 logs bucket should enable server access logging",
                "Description": f"AWS CloudTrail trail {trailName} Amazon S3 logs bucket does enable server access logging.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Amazon S3 Server Access Logging section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_s3_read_and_write_data_events_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.8] AWS CloudTrail trails should record Amazon S3 Read and Write Data Events"""
    cloudtrail = session.client("cloudtrail")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Get Event Selectors, if there are not any filters for Management Events or Data Events at all, this will fail
        try:
            dataEvents = cloudtrail.get_event_selectors(TrailName=trail["TrailARN"])
            if not "AdvancedEventSelectors" in dataEvents:
                allS3DataEvents = False
            else:
            # Check if there is a combination of eventCategory and resources.Type matching the desired values
                dataEventsCaptured = False
                s3ReadAndWrite = False
                for eventSelector in dataEvents["AdvancedEventSelectors"]:
                    fieldSelectors = eventSelector.get("FieldSelectors", [])
                    # Look for the right combos of Data Event and S3 log types and override the above Bools
                    for fieldSelector in fieldSelectors:
                        field = fieldSelector.get("Field", "")
                        equals = fieldSelector.get("Equals", [])
                        # Data Events within the "Advanced" selectors for CloudTrail
                        if field == "eventCategory" and "Data" in equals:
                            dataEventsCaptured = True
                        # "AWS::S3::Object" in the supported Resources, this is both Read and Write Data Events
                        if field == "resources.type" and "AWS::S3::Object" in equals:
                            s3ReadAndWrite = True
                    # Finish up if both are true
                    if dataEventsCaptured and s3ReadAndWrite:
                        allS3DataEvents = True
                        break
                else:
                    allS3DataEvents = False
        except ClientError:
            allS3DataEvents = False

        # this is a failing check
        if allS3DataEvents is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-read-write-data-events-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-read-write-data-events-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudTrail.8] AWS CloudTrail trails should record Amazon S3 Read and Write Data Events",
                "Description": f"AWS CloudTrail trail {trailName} does not record Amazon S3 Read and Write Data Events. By default, trails and event data stores do not log data events and dditional charges do apply for data events. Data events provide visibility into the resource operations performed on or within a resource. These are also known as data plane operations. Data events are often high-volume activities. Amazon S3 Data Events capture object-level API activity (for example, GetObject, DeleteObject, and PutObject API operations) on buckets and objects in buckets. If you are logging data events for specific Amazon S3 buckets, we recommend you do not use an Amazon S3 bucket for which you are logging data events to receive log files that you have specified in the data events section. Using the same Amazon S3 bucket causes your trail or event data store to log a data event each time log files are delivered to your Amazon S3 bucket. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring S3 Data Events for your trails refer to the Logging data events section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.10",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.11"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-s3-read-write-data-events-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-s3-read-write-data-events-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.8] AWS CloudTrail trails should record Amazon S3 Read and Write Data Events",
                "Description": f"AWS CloudTrail trail {trailName} does record Amazon S3 Read and Write Data Events.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring S3 Data Events for your trails refer to the Logging data events section of the AWS CloudTrail User Guide",
                        "Url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.10",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.11"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_unauth_api_calls_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.9] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor unauthorized API calls"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) || ($.sourceIPAddress!=delivery.logs.amazonaws.com) || ($.eventName!=HeadBucket) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-unauthorized-api-calls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-unauthorized-api-calls-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.9] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor unauthorized API calls",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor unauthorized API calls or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for unauthorized API calls. Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity. This alert may be triggered by normal read-only console activities that attempt to opportunistically gather optional information, but gracefully fail if they don't have permissions. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-unauthorized-api-calls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-unauthorized-api-calls-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.9] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor unauthorized API calls",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor unauthorized API calls configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding 

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_console_login_no_mfa_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.10] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Management Console sign-in without MFA"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-login-no-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-login-no-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.10] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Management Console sign-in without MFA",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor Management Console sign-in without MFA or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for console logins that are not protected by multi-factor authentication (MFA). Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-login-no-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-login-no-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.10] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Management Console sign-in without MFA",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor Management Console sign-in without MFA.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_root_user_usage_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.11] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor usage of 'root' account"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-root-account-usage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-root-account-usage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.11] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor usage of 'root' account",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor usage of 'root' account or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for 'root' login attempts. Monitoring for 'root' account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-root-account-usage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-root-account-usage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.11] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor usage of 'root' account",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor usage of 'root' account.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSEd",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_iam_policy_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.12] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor IAM policy changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-iam-policy-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-iam-policy-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.12] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor IAM policy changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor IAM policy changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies. Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-iam-policy-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-iam-policy-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.12] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor IAM policy changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor IAM policy changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_cloudtrail_config_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.13] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor CloudTrail configuration changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-cloudtrail-config-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-cloudtrail-config-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.13] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor CloudTrail configuration changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor CloudTrail configuration changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-cloudtrail-config-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-cloudtrail-config-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.13] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor CloudTrail configuration changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor CloudTrail configuration changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_console_authentication_failures_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.14] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Management Console authentication failures"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-auth-failures-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-auth-failures-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.14] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Management Console authentication failures",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor AWS Management Console authentication failures or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts. Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-auth-failures-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-console-auth-failures-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.14] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Management Console authentication failures",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor AWS Management Console authentication failures.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_disable_or_delete_aws_kms_cmks_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.15] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor disabling or scheduled deletion of customer created AWS KMS CMKs"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion)) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-disable-or-deleton-aws-kms-cmks-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-disable-or-deleton-aws-kms-cmks-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.15] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor disabling or scheduled deletion of customer created AWS KMS CMKs",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor disabling or scheduled deletion of customer created AWS KMS CMKs or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion. Data encrypted with disabled or deleted keys will no longer be accessible. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-disable-or-deleton-aws-kms-cmks-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-disable-or-deleton-aws-kms-cmks-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.15] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor disabling or scheduled deletion of customer created AWS KMS CMKs",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor disabling or scheduled deletion of customer created AWS KMS CMKs.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_s3_bucket_policy_change_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.16] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon S3 bucket policy changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-s3-bucket-policy-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-s3-bucket-policy-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.16] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon S3 bucket policy changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor Amazon S3 bucket policy changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for changes to S3 bucket policies. Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.8"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-s3-bucket-policy-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-s3-bucket-policy-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.16] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon S3 bucket policy changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor Amazon S3 bucket policy changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.8"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_aws_config_configuration_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.17] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Config configuration changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder)) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-config-configuration-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-config-configuration-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.17] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Config configuration changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor AWS Config configuration changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail's configurations. Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.9"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-config-configuration-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-config-configuration-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.17] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Config configuration changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor AWS Config configuration changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.9"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_security_group_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.18] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS EC2 security group changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-security-groups-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-security-groups-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.18] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS EC2 security group changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor AWS EC2 security group changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingress and egress traffic within a VPC. It is recommended that a metric filter and alarm be established for detecting changes to Security Groups. Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.10"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-security-groups-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-security-groups-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.18] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS EC2 security group changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor AWS EC2 security group changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.10"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_nacl_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.19] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC Network Access Control Lists (NACL) changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-nacl-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-nacl-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.19] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC Network Access Control Lists (NACL) changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor Amazon VPC Network Access Control Lists (NACL) changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets within a VPC. It is recommended that a metric filter and alarm be established for changes made to NACLs. Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.11"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-nacl-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-nacl-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.19] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC Network Access Control Lists (NACL) changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor Amazon VPC Network Access Control Lists (NACL) changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.11"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_network_gateway_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.20] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor network gateway changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-network-gateway-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-network-gateway-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.20] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor network gateway changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor network gateway changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Network gateways are required to send/receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways. Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.12"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-network-gateway-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-network-gateway-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.20] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor network gateway changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor network gateway changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.12"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_vpc_route_table_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.21] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC route table changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-route-table-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-route-table-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.21] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC route table changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor Amazon VPC route table changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables. Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.13"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-route-table-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-route-table-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.21] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC route table changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor Amazon VPC route table changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.13"
                    ]
                },
                "Workflow": {"Status": "PASSED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_vpc_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.22] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-vpc-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-vpc-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.22] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor Amazon VPC changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs. Monitoring changes to VPC will help ensure VPC traffic flow is not getting impacted. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.14"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-vpc-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-vpc-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.22] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor Amazon VPC changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor Amazon VPC changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.14"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudtrail")
def cloudtrail_cloudwatch_metric_alarm_aws_organizations_changes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudTrail.23] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Organizations changes"""
    # CloudWatch Logs & CloudWatch Client
    logs = session.client("logs")
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for trail in get_all_shadow_trails(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(trail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        trailArn = trail["TrailARN"]
        trailName = trail["Name"]
        # Set the "passing state" of the check, this can be overriden in multiple ways
        filterAlarmPassing = True
        # This is a compound check as we need to ensure CloudWatch Logs exist for the Trail, are located in the Account being assessed,
        # and then that the metrics exist and have an alarm assigned for them
        if "CloudWatchLogsLogGroupArn" in trail:
            logGroupArn = trail["CloudWatchLogsLogGroupArn"]
            logGroupAccount = logGroupArn.split(":")[4]
            logGroupRegion = logGroupArn.split(":")[3]
            logGroupName = logGroupArn.split(":")[6]
            if awsAccountId != logGroupAccount:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed account (%s) and cannot be assessed.",
                    trailName, awsAccountId
                )
            if awsRegion != logGroupRegion:
                logger.info(
                    "AWS CloudTrail trail %s has an attached CloudWatch Logs Group that is not located in the currently assessed region (%s) and cannot be assessed.",
                    trailName, awsRegion
                )
            else:
                # Pull out the filters for the Log Group
                metricFilters = logs.describe_metric_filters(
                    logGroupName=logGroupName,
                )["metricFilters"]
                # Check if any filter matches the pattern being assessed
                filterPattern = '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'
                matchedPatterns = [filters for filters in metricFilters if filterPattern == filters["filterPattern"]]
                # if there is content, we have match, now to check the alarm
                if matchedPatterns:
                    filterAlarmPassing = True
                    # check if the metric & namespace combo have an alarm
                    alarmCheck = cloudwatch.describe_alarms_for_metric(
                        MetricName=matchedPatterns[0]["metricTransformations"][0]["metricName"],
                        Namespace=matchedPatterns[0]["metricTransformations"][0]["metricNamespace"]
                    )["MetricAlarms"]
                    if not alarmCheck:
                        filterAlarmPassing = False
                else:
                    filterAlarmPassing = False
        else:
            filterAlarmPassing = False

        # this is a failing check
        if filterAlarmPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-organizations-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-organizations-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudTrail.23] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Organizations changes",
                "Description": f"AWS CloudTrail trail {trailName} does not have a metric and alarm configured to monitor AWS Organizations changes or it does not have a CloudWatch Logs group associated. Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for AWS Organizations changes made in the master AWS Account. Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.15"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-organizations-changes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{trailArn}/cloudtrail-cloudwatch-metric-alarm-aws-organizations-changes-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudTrail.23] AWS CloudTrail trails should have CloudWatch metrics and alarms configured to monitor AWS Organizations changes",
                "Description": f"AWS CloudTrail trail {trailName} does have a metric and alarm configured to monitor AWS Organizations changes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Refer to the Remediation section of the AWS CIS Foundations Benchmark corresponding to the metric filter to learn how to build it programmatically. To generally learn how to create Metrics and Alarms refer to the Using Amazon CloudWatch alarms section of the Amazon CloudWatch User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
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
                    "AssetService": "AWS CloudTrail",
                    "AssetComponent": "Trail"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": trailArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 4.15"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## EOF?