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
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

@registry.register_check('xray')
def xray_kms_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[XRAY.1] X-Ray Encryption Configuration should use a KMS CMK"""
    xray = session.client('xray')
    # Check the encryption config for X-Ray. It uses AES-256 by default, but we're looking for KMS
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    response = xray.get_encryption_config()['EncryptionConfig']
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(response,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
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
            "Title": "[XRay.1] X-Ray Encryption Configuration should use a KMS CMK",
            "Description": "The AWS X-Ray Encryption Configuration for Account "
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
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Developer Tools",
                "AssetService": "AWS XRay",
                "AssetType": "Encryption Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsXrayEncryptionConfig",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/AWS_XRay_Encryption_Configuration",
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
            "Title": "[XRay.1] X-Ray Encryption Configuration should use a KMS CMK",
            "Description": "The AWS X-Ray Encryption Configuration for Account "
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
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Developer Tools",
                "AssetService": "AWS XRay",
                "AssetType": "Encryption Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsXrayEncryptionConfig",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/AWS_XRay_Encryption_Configuration",
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
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding