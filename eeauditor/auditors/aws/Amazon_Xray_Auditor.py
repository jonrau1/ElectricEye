'''
This file is part of ElectricEye.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

xray = boto3.client('xray')

@registry.register_check('xray')
def xray_kms_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[XRAY.1] X-Ray Encryption Configure should use a KMS CMK"""
    # Check the encryption config for X-Ray. It uses AES-256 by default, but we're looking for KMS
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    response = xray.get_encryption_config()['EncryptionConfig']
    if str(response['Type']) == 'NONE':
        # This is a failing finding
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/xray-kms-cmk-encryption-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion + "xray-encryption",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[XRay.1] X-Ray Encryption Configure should use a KMS CMK",
            "Description": "The AWS X-Ray Encryption Configure for Account "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " is not using a KMS CMK. Refer to the remediation instructions to remediate this behavior",
            "Remediation": {
                "Recommendation": {
                    "Text": "AWS X-Ray always encrypts traces and related data at rest. When you need to audit and disable encryption keys for compliance or internal requirements, you can configure X-Ray to use an AWS Key Management Service (AWS KMS) customer master key (CMK) to encrypt data. See Data Protection in AWS X-Ray for more information.",
                    "Url": "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsXrayEncryptionConfiguration",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.DS-1",
                    "NIST SP 800-53 MP-8",
                    "NIST SP 800-53 SC-12",
                    "NIST SP 800-53 SC-28",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding
    else:
        # This is a passing finding
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/xray-kms-cmk-encryption-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion + "xray-encryption",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[XRay.1] X-Ray Encryption Configure should use a KMS CMK",
            "Description": "The AWS X-Ray Encryption Configure for Account "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " is using a KMS CMK.",
            "Remediation": {
                "Recommendation": {
                    "Text": "AWS X-Ray always encrypts traces and related data at rest. When you need to audit and disable encryption keys for compliance or internal requirements, you can configure X-Ray to use an AWS Key Management Service (AWS KMS) customer master key (CMK) to encrypt data. See Data Protection in AWS X-Ray for more information.",
                    "Url": "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsXrayEncryptionConfiguration",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.DS-1",
                    "NIST SP 800-53 MP-8",
                    "NIST SP 800-53 SC-12",
                    "NIST SP 800-53 SC-28",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding