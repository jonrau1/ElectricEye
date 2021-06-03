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
import json
import os
from check_register import CheckRegister

registry = CheckRegister()
kms = boto3.client("kms")

def list_keys(cache):
    response = cache.get("list_keys")
    if response:
        return response
    cache["list_keys"] = kms.list_keys()
    return cache["list_keys"]

def list_aliases(cache):
    response = cache.get("list_aliases")
    if response:
        return response
    cache["list_aliases"] = kms.list_aliases()
    return cache["list_aliases"]


@registry.register_check("kms")
def kms_key_rotation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.1] KMS keys should have key rotation enabled"""
    keys = list_keys(cache=cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for key in keys["Keys"]:
        keyid = key["KeyId"]
        keyarn = key["KeyArn"]
        key_rotation = kms.get_key_rotation_status(KeyId=keyid)
        if key_rotation["KeyRotationEnabled"] == True:
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
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

@registry.register_check("kms")
def kms_key_exposed_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[KMS.2] KMS keys should not have public access"""
    response = list_aliases(cache=cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for alias in response["Aliases"]:
        if "TargetKeyId" in alias:
            aliasArn = alias["AliasArn"]
            keyid = alias["TargetKeyId"]
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKmsAlias",
                            "Id": aliasArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "PASSED"},
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKmsAlias",
                            "Id": aliasArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "FAILED"},
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding