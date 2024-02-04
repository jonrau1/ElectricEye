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

def list_keys(cache, session):
    response = cache.get("list_keys")
    if response:
        return response
    
    kms = session.client("kms")

    cache["list_keys"] = kms.list_keys()["Keys"]
    return cache["list_keys"]

@registry.register_check("kms")
def kms_key_rotation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.1] AWS KMS symmetric keys should enable automatic key rotation"""
    kms = session.client("kms")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for key in list_keys(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(key,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        keyid = key["KeyId"]
        keyarn = key["KeyArn"]
        # KMS Key Policies can block us from snooping the type of Key - in the event we run into an issue we have to handle it gracefully
        try:
            keyData = kms.describe_key(KeyId=keyid)
            # override the asset info
            del assetB64
            assetB64 = base64.b64encode(json.dumps(keyData,default=str).encode("utf-8"))
            # Auto-pass the asymmetric keys
            if keyData["KeyMetadata"]["KeyUsage"] == "SIGN_VERIFY":
                rotationEnabled = True
            else:
                rotationEnabled = kms.get_key_rotation_status(KeyId=keyid)["KeyRotationEnabled"]
        except ClientError:
            rotationEnabled = False

        # this is a passing check
        if rotationEnabled is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{keyarn}/kms-key-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{keyarn}/kms-key-rotation-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[KMS.1] AWS KMS symmetric keys should enable automatic key rotation",
                "Description": f"AWS KMS key {keyid} either enables automatic rotation or is an asymmetric key, and thus, cannot be automatically rotated and automatically passes this check - no pun intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling automatic KMS key rotation refer to the AWS KMS Developer Guide on Rotating Keys",
                        "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Key Management Service",
                    "AssetComponent": "Key"
                },
                "Resources": [
                    {
                        "Type": "AwsKmsKey",
                        "Id": keyarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsKmsKey": {"KeyId": keyid}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.8",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.8"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{keyarn}/kms-key-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{keyarn}/kms-key-rotation-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[KMS.1] AWS KMS symmetric keys should enable automatic key rotation",
                "Description": f"AWS KMS key {keyid} does not enable automatic rotation or the Key Policy did not allow ElectricEye to describe the key to determine if it was an asymmetric key or not. When you enable automatic key rotation for a KMS key, AWS KMS generates new cryptographic material for the KMS key every year. AWS KMS saves all previous versions of the cryptographic material in perpetuity so you can decrypt any data encrypted with that KMS key. AWS KMS does not delete any rotated key material until you delete the KMS key. You can track the rotation of key material for your KMS keys in Amazon CloudWatch and AWS CloudTrail. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling automatic KMS key rotation refer to the AWS KMS Developer Guide on Rotating Keys",
                        "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Key Management Service",
                    "AssetComponent": "Key"
                },
                "Resources": [
                    {
                        "Type": "AwsKmsKey",
                        "Id": keyarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsKmsKey": {"KeyId": keyid}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.8",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.8"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("kms")
def kms_key_exposed_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.2] AWS KMS keys should not be publicly exposed to every AWS principal"""
    kms = session.client("kms")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for key in list_keys(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(key,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        keyid = key["KeyId"]
        keyarn = key["KeyArn"]
        # KMS Key Policies can block us from snooping the type of Key - in the event we run into an issue we have to handle it gracefully
        try:
            keyData = kms.describe_key(KeyId=keyid)
            # override the asset info
            del assetB64
            assetB64 = base64.b64encode(json.dumps(keyData,default=str).encode("utf-8"))
            # Pull out the Policy
            policy = json.loads(
                kms.get_key_policy(KeyId=keyid, PolicyName="default")["Policy"]
            )
            keyExposureStatus = "NOT_EXPOSED"
            # Begin policy eval
            for sid in policy["Statement"]:
                if sid["Principal"] == "*":
                    access = "*"
                else:
                    access = sid["Principal"].get("AWS", None)
                if access != "*" or (access == "*" and "Condition" in sid):
                    continue
                else:
                    keyExposureStatus = "EXPOSED"
                    break
        except ClientError or KeyError:
            keyExposureStatus = "UNKNOWN"

        # Parse the the different failure conditions we set - this will modify some details in the finding
        if keyExposureStatus == "EXPOSED":
            severityLabel = "CRITICAL"
            reason = "is publicly exposed because the Key Policy defines a Principal of '{'AWS': '*'}' without an additional Condition."
        elif keyExposureStatus == "UNKNOWN":
            severityLabel = "MEDIUM"
            reason = "is unable to be assessed for the Key Policy allowing public exposure because the Key Policy is blocking ElectricEye from accessing one or both of the DescribeKey and/or GetKeyPolicy APIs."
        else:
            severityLabel = "INFORMATIONAL"
            reason = "is not publicly exposed because the Key Policy either does not define a Principal of '{'AWS': '*'}' or if it does, it specificies Conditions."

        if keyExposureStatus == ("EXPOSED" or "UNKNOWN"):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{keyarn}/kms-key-exposed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{keyarn}/kms-key-exposed-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                    "Sensitive Data Identifications",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": severityLabel},
                "Confidence": 99,
                "Title": "[KMS.2] AWS KMS keys should not be publicly exposed to every AWS principal",
                "Description": f"AWS KMS key {keyid} {reason} When the Principal element value is set to '*' (effectively, any AWS Account) within the CMK policy and there is no Condition clause defined, anyone can access the specified key. One common scenario is when the Amazon KMS administrator grants access for everyone to use the key but forgets adding the Condition clause to the key policy in order to filter the access to certain (trusted) entities only. Allowing unrestricted access to your customer-managed Customer Master Keys (CMKs) is a bad practice as it undermines the integrity of the encryption and can be used to decrypt sensitive data or even the maliciously encrypt your own resources in a ransomware-by-proxy attack. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Key Management Service",
                    "AssetComponent": "Key"
                },
                "Resources": [
                    {
                        "Type": "AwsKmsAlias",
                        "Id": keyarn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
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
                        "ISO 27001:2013 A.11.2.6",
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
                "Id": f"{keyarn}/kms-key-exposed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{keyarn}/kms-key-exposed-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                    "Sensitive Data Identifications",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": severityLabel},
                "Confidence": 99,
                "Title": "[KMS.2] AWS KMS keys should not be publicly exposed to every AWS principal",
                "Description": f"AWS KMS key {keyid} {reason}",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Amazon Key Management Service",
                    "AssetComponent": "Key"
                },
                "Resources": [
                    {
                        "Type": "AwsKmsAlias",
                        "Id": keyarn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
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
                        "ISO 27001:2013 A.11.2.6",
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

## EOF ??