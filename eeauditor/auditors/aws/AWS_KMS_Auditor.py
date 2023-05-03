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
import botocore.exceptions
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def list_keys(cache, session):
    kms = session.client("kms")
    response = cache.get("list_keys")
    if response:
        return response
    cache["list_keys"] = kms.list_keys()
    return cache["list_keys"]

def list_aliases(cache, session):
    kms = session.client("kms")
    response = cache.get("list_aliases")
    if response:
        return response
    cache["list_aliases"] = kms.list_aliases()
    return cache["list_aliases"]

@registry.register_check("kms")
def kms_key_rotation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.1] KMS keys should have key rotation enabled"""
    kms = session.client("kms")
    keys = list_keys(cache, session)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for key in keys["Keys"]:
        keyid = key["KeyId"]
        keyarn = key["KeyArn"]
        try:
            # Check to make sure that we have a Symmetric Key
            keyData = kms.describe_key(KeyId=keyid)
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(keyData,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            keyUse = keyData["KeyMetadata"]["KeyUsage"]
            if keyUse == "SIGN_VERIFY":
                continue

            # We have a Sym Key at this point, continue...
            key_rotation = kms.get_key_rotation_status(KeyId=keyid)
            if key_rotation["KeyRotationEnabled"] == True:
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": keyarn + "/kms-key-rotation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": keyarn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[KMS.1] KMS keys should have key rotation enabled",
                    "Description": "KMS Key " + keyid + " does have key rotation enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on KMS key rotation refer to the AWS KMS Developer Guide on Rotating Keys",
                            "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
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
                            "Details": {"AwsKmsKey": {"KeyId": keyid}},
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
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": keyarn + "/kms-key-rotation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": keyarn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[KMS.1] KMS keys should have key rotation enabled",
                    "Description": "KMS key "
                    + keyid
                    + " does not have key rotation enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on KMS key rotation refer to the AWS KMS Developer Guide on Rotating Keys",
                            "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
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
                            "Details": {"AwsKmsKey": {"KeyId": keyid}},
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                # If the KMS Key Policy does not give us access to check rotation we should still create a failed check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": keyarn + "/kms-key-rotation-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": keyarn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[KMS.1] KMS keys should have key rotation enabled",
                    "Description": f"KMS key {keyarn} has a Key Policy that did not allow the Profile that ran ElectricEye last permissions to check Key Rotation Status. You should manually check to ensure rotation is enabled, and if not, refer to the remediation instructions to fix this if not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on KMS key rotation refer to the AWS KMS Developer Guide on Rotating Keys",
                            "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
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
                            "Details": {"AwsKmsKey": {"KeyId": keyid}},
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(f'We found another error! {error}')

@registry.register_check("kms")
def kms_key_exposed_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.2] KMS keys should not have public access"""
    kms = session.client("kms")
    response = list_aliases(cache, session)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for alias in response["Aliases"]:
        if "TargetKeyId" in alias:
            aliasArn = alias["AliasArn"]
            keyid = alias["TargetKeyId"]
            try:
                keyData = kms.describe_key(KeyId=keyid)
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(keyData,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                policyString = kms.get_key_policy(KeyId=keyid, PolicyName="default")
                fail = False
                policy_json = policyString["Policy"]
                policy = json.loads(policy_json)
                for sid in policy["Statement"]:
                    if sid["Principal"] == "*":
                        access = "*"
                    else:
                        access = sid["Principal"].get("AWS", None)
                    if access != "*" or (access == "*" and "Condition" in sid):
                        continue
                    else:
                        fail = True
                        break
                if not fail:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": aliasArn + "/kms-key-exposed-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": aliasArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 75,  # The Condition may not effectively limit access
                        "Title": "[KMS.2] KMS keys should not have public access",
                        "Description": "KMS key "
                        + keyid
                        + " does not have public access or limited by a Condition. Refer to the remediation instructions to review kms access policy",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                                "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
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
                            "AssetComponent": "Key Alias"
                        },
                        "Resources": [
                            {
                                "Type": "AwsKmsAlias",
                                "Id": aliasArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
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
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": aliasArn + "/kms-key-exposed-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": aliasArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[KMS.2] KMS keys should not have public access",
                        "Description": "KMS key "
                        + keyid
                        + " has public access. Refer to the remediation instructions to review kms access policy",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on AWS KMS key policies refer to Using key policies in AWS KMS section of the AWS KMS Developer Guide.",
                                "Url": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
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
                            "AssetComponent": "Key Alias"
                        },
                        "Resources": [
                            {
                                "Type": "AwsKmsAlias",
                                "Id": aliasArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
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
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    continue
                else:
                    print(f'We found another error! {error}')