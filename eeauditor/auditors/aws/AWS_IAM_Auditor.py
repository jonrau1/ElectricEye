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
import json

registry = CheckRegister()
# import boto3 clients
iam = boto3.client("iam")
# loop through IAM users
def list_users(cache):
    response = cache.get("list_users")
    if response:
        return response
    cache["list_users"] = iam.list_users(MaxItems=1000)
    return cache["list_users"]

@registry.register_check("iam")
def iam_access_key_age_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.1] IAM Access Keys should be rotated every 90 days"""
    user = list_users(cache=cache)
    for users in user["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        try:
            response = iam.list_access_keys(UserName=userName)
            for keys in response["AccessKeyMetadata"]:
                keyUserName = str(keys["UserName"])
                keyId = str(keys["AccessKeyId"])
                keyStatus = str(keys["Status"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if keyStatus == "Active":
                    keyCreateDate = keys["CreateDate"]
                    todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
                    keyAgeFinder = todaysDatetime - keyCreateDate
                    if keyAgeFinder <= datetime.timedelta(days=90):
                        # this is a passing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": keyUserName + keyId + "/iam-access-key-age-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": userArn + keyId,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[IAM.1] IAM Access Keys should be rotated every 90 days",
                            "Description": "IAM access key "
                            + keyId
                            + " for user "
                            + keyUserName
                            + " is not over 90 days old.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsIamAccessKey",
                                    "Id": userArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsIamAccessKey": {
                                            "PrincipalId": keyId,
                                            "PrincipalName": keyUserName,
                                            "Status": keyStatus,
                                        }
                                    },
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
                            "Id": keyUserName + keyId + "/iam-access-key-age-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": userArn + keyId,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[IAM.1] IAM Access Keys should be rotated every 90 days",
                            "Description": "IAM access key "
                            + keyId
                            + " for user "
                            + keyUserName
                            + " is over 90 days old. As a security best practice, AWS recommends that you regularly rotate (change) IAM user access keys. If your administrator granted you the necessary permissions, you can rotate your own access keys. Refer to the remediation section to remediate this behavior.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsIamAccessKey",
                                    "Id": userArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsIamAccessKey": {
                                            "PrincipalId": keyId,
                                            "PrincipalName": keyUserName,
                                            "Status": keyStatus,
                                        }
                                    },
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
                else:
                    pass
        except Exception as e:
            print(e)

@registry.register_check("iam")
def user_permission_boundary_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """aaa"""
    user = list_users(cache=cache)
    for users in user["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            permBoundaryArn = str(users["PermissionsBoundary"]["PermissionsBoundaryArn"])
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": userArn + "/iam-user-permissions-boundary-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAM.2] IAM users should have permissions boundaries attached",
                "Description": "IAM user " + userName + " has a permissions boundary attached.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on permissions boundaries refer to the Permissions Boundaries for IAM Entities section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "PrincipalName": userName,
                                "permissionsBoundaryArn": permBoundaryArn,
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-4",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-5",
                        "NIST SP 800-53 AC-6",
                        "NIST SP 800-53 AC-14",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except Exception as e:
            if str(e) == "'PermissionsBoundary'":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-permissions-boundary-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[IAM.2] IAM users should have permissions boundaries attached",
                    "Description": "IAM user "
                    + userName
                    + " does not have a permissions boundary attached. A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. A permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Refer to the remediation section to remediate this behavior.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on permissions boundaries refer to the Permissions Boundaries for IAM Entities section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-5",
                            "NIST SP 800-53 AC-6",
                            "NIST SP 800-53 AC-14",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-24",
                            "AICPA TSC CC6.3",
                            "ISO 27001:2013 A.6.1.2",
                            "ISO 27001:2013 A.9.1.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.4.1",
                            "ISO 27001:2013 A.9.4.4",
                            "ISO 27001:2013 A.9.4.5",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(e)

@registry.register_check("iam")
def user_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.3] IAM users should have Multi-Factor Authentication (MFA) enabled"""
    user = list_users(cache=cache)
    for users in user["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = iam.list_mfa_devices(UserName=userName)
            if str(response["MFADevices"]) == "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-mfa-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[IAM.3] IAM users should have Multi-Factor Authentication (MFA) enabled",
                    "Description": "IAM user "
                    + userName
                    + " does not have MFA enabled. For increased security, AWS recommends that you configure multi-factor authentication (MFA) to help protect your AWS resources. Refer to the remediation section to remediate this behavior.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-mfa-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.3] IAM users should have Multi-Factor Authentication (MFA) enabled",
                    "Description": "IAM user " + userName + " has MFA enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
        except Exception as e:
            print(e)

@registry.register_check("iam")
def user_inline_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.4] IAM users should not have attached in-line policies"""
    user = list_users(cache=cache)
    allUsers = user["Users"]
    for users in allUsers:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = iam.list_user_policies(UserName=userName)
            if str(response["PolicyNames"]) != "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-attach-inline-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[IAM.4] IAM users should not have attached in-line policies",
                    "Description": "IAM user "
                    + userName
                    + " has an in-line policy attached. It is recommended that IAM policies be applied directly to groups and roles but not users. Refer to the remediation section to remediate this behavior.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-attach-inline-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.4] IAM users should not have attached in-line policies",
                    "Description": "IAM user "
                    + userName
                    + " does not have an in-line policy attached.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
        except Exception as e:
            print(e)

@registry.register_check("iam")
def user_direct_attached_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.5] IAM users should not have attached managed policies"""
    user = list_users(cache=cache)
    allUsers = user["Users"]
    for users in allUsers:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = iam.list_attached_user_policies(UserName=userName)
            if str(response["AttachedPolicies"]) != "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-attach-managed-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[IAM.5] IAM users should not have attached managed policies",
                    "Description": "IAM user "
                    + userName
                    + " has a managed policy attached. It is recommended that IAM policies be applied directly to groups and roles but not users. Refer to the remediation section to remediate this behavior.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/iam-user-attach-managed-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.5] IAM users should not have attached managed policies",
                    "Description": "IAM user "
                    + userName
                    + " does not have a managed policy attached.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"PrincipalName": userName}},
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
        except Exception as e:
            print(e)

@registry.register_check("iam")
def cis_aws_foundation_benchmark_pw_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard"""
    try:
        # TODO: if no policy is found, this will throw an exception in
        # which case we need to create an ACTIVE finding
        response = iam.get_account_password_policy()
        pwPolicy = response["PasswordPolicy"]
        minPwLength = int(pwPolicy["MinimumPasswordLength"])
        symbolReq = str(pwPolicy["RequireSymbols"])
        numberReq = str(pwPolicy["RequireNumbers"])
        uppercaseReq = str(pwPolicy["RequireUppercaseCharacters"])
        lowercaseReq = str(pwPolicy["RequireLowercaseCharacters"])
        maxPwAge = int(pwPolicy["MaxPasswordAge"])
        pwReuse = int(pwPolicy["PasswordReusePrevention"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if (
            minPwLength >= 14
            and maxPwAge <= 90
            and pwReuse >= 24
            and symbolReq == "True"
            and numberReq == "True"
            and uppercaseReq == "True"
            and lowercaseReq == "True"
        ):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/cis-aws-foundations-benchmark-pw-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "iam-password-policy",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard",
                "Description": "The IAM password policy for account "
                + awsAccountId
                + " meets or exceeds the AWS CIS Foundations Benchmark standard.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on the CIS AWS Foundations Benchmark standard for the password policy refer to the linked Standard",
                        "Url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
                "Id": awsAccountId + "/cis-aws-foundations-benchmark-pw-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "iam-password-policy",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard",
                "Description": "The IAM password policy for account "
                + awsAccountId
                + " does not meet the AWS CIS Foundations Benchmark standard. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on the CIS AWS Foundations Benchmark standard for the password policy refer to the linked Standard",
                        "Url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
    except Exception as e:
        print(e)

@registry.register_check("iam")
def server_certs_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.7] There should not be any server certificates stored in AWS IAM"""
    try:
        response = iam.list_server_certificates()
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(response["ServerCertificateMetadataList"]) != "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/server-x509-certs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "server-cert",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
                "Description": "There are server certificates stored in AWS IAM for the account "
                + awsAccountId
                + ". ACM is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. Certificates provided by ACM are free and automatically renew. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on server certificates refer to the Working with Server Certificates section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/server-x509-certs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + "server-cert",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
                "Description": "There are not server certificates stored in AWS IAM for the account "
                + awsAccountId
                + ".",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on server certificates refer to the Working with Server Certificates section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
    except Exception as e:
        print(e)


@registry.register_check("iam")
def iam_mngd_policy_least_priv_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.8] Managed policies should follow least privilege principles"""
    try:
        policies = iam.list_policies(Scope='Local')
        for mngd_policy in policies['Policies']:
            policy_arn = mngd_policy['Arn']
            version_id = mngd_policy['DefaultVersionId']

            policy_doc = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )['PolicyVersion']['Document']
            #handle policies docs returned as strings
            if type(policy_doc) == str:
                policy_doc = json.loads(policy_doc)

            least_priv_rating = 'passing'
            for statement in policy_doc['Statement']:
                if statement["Effect"] == 'Allow':
                    if statement.get('Condition') == None: 
                        # action structure could be a string or a list
                        if type(statement['Action']) == list: 
                            if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                if type(statement['Resource']) == str and statement['Resource'] == '*':
                                    least_priv_rating = 'failed_high'
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement['Resource']) == list: 
                                    least_priv_rating = 'failed_low'

                        # Single action in a statement
                        elif type(statement['Action']) == str:
                            if ":*" in statement['Action'] or statement['Action'] == '*':
                                if type(statement['Resource']) == str and statement['Resource'] == '*':
                                    least_priv_rating = 'failed_high'
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement['Resource']) == list: 
                                    least_priv_rating = 'failed_low'

            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            if least_priv_rating == 'passing':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": policy_arn + "/mngd_policy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policy_arn + "mngd_policy_least_priv",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policy_arn} is following least privilege principles.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policy_arn,
                            "Partition": awsPartition,
                            "Region": awsRegion
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-3",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-17",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-20",
                            "NIST SP 800-53 SC-15",
                            "AICPA TSC CC6.6",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            elif least_priv_rating == 'failed_low':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": policy_arn + "/mngd_policy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policy_arn + "mngd_policy_least_priv",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policy_arn} is not following least privilege principles and has been rated: {least_priv_rating}.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policy_arn,
                            "Partition": awsPartition,
                            "Region": awsRegion
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-3",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-17",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-20",
                            "NIST SP 800-53 SC-15",
                            "AICPA TSC CC6.6",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            elif least_priv_rating == 'failed_high':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": policy_arn + "/mngd_policy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policy_arn + "mngd_policy_least_priv",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policy_arn} is not following least privilege principles and has been rated: {least_priv_rating}.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policy_arn,
                            "Partition": awsPartition,
                            "Region": awsRegion
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-3",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-17",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-20",
                            "NIST SP 800-53 SC-15",
                            "AICPA TSC CC6.6",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
    except: 
        pass


@registry.register_check("iam")
def iam_user_policy_least_priv_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.9] User inline policies should follow least privilege principles"""
    try:
        Users = iam.list_users()
        for user in Users['Users']:
            user_arn = user['Arn']
            UserName = user['UserName']

            policy_names = iam.list_user_policies(
                UserName=UserName
            )['PolicyNames']
            for policy_name in policy_names:
                policy_doc = iam.get_user_policy(
                    UserName=UserName,
                    PolicyName=policy_name
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policy_doc) == str:
                    policy_doc = json.loads(policy_doc)

                least_priv_rating = 'passing'
                for statement in policy_doc['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if least_priv_rating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": user_arn + "/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": user_arn + "user_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {user_arn} inline policy {policy_name} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                        {
                        "Type": "AwsIamUser",
                        "Id": user_arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "PrincipalName": UserName
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif least_priv_rating == 'failed_low':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": user_arn + "/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": user_arn + "user_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {user_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                        {
                        "Type": "AwsIamUser",
                        "Id": user_arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "PrincipalName": UserName
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif least_priv_rating == 'failed_high':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": user_arn + "/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": user_arn + "user_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {user_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                        {
                        "Type": "AwsIamUser",
                        "Id": user_arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                    "PrincipalName": UserName
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except: 
        pass


@registry.register_check("iam")
def iam_group_policy_least_priv_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.10] Group inline policies should follow least privilege principles"""
    try:
        Groups = iam.list_groups()
        for group in Groups['Groups']:
            group_arn = group['Arn']
            GroupName = group['GroupName']

            policy_names = iam.list_group_policies(
                GroupName=GroupName
            )['PolicyNames']
            for policy_name in policy_names:
                policy_doc = iam.get_group_policy(
                    GroupName=GroupName,
                    PolicyName=policy_name
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policy_doc) == str:
                    policy_doc = json.loads(policy_doc)

                least_priv_rating = 'passing'
                for statement in policy_doc['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if least_priv_rating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": group_arn + "/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": group_arn + "group_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {group_arn} inline policy {policy_name} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": group_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif least_priv_rating == 'failed_low':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": group_arn + "/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": group_arn + "group_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {group_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": group_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif least_priv_rating == 'failed_high':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": group_arn + "/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": group_arn + "group_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {group_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": group_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except: 
        pass


@registry.register_check("iam")
def iam_role_policy_least_priv_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.11] Role inline policies should follow least privilege principles"""
    try:
        Roles = iam.list_roles()
        for role in Roles['Roles']:
            role_arn = role['Arn']
            RoleName = role['RoleName']

            policy_names = iam.list_role_policies(
                RoleName=RoleName
            )['PolicyNames']
            for policy_name in policy_names:
                policy_doc = iam.get_role_policy(
                    RoleName=RoleName,
                    PolicyName=policy_name
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policy_doc) == str:
                    policy_doc = json.loads(policy_doc)

                least_priv_rating = 'passing'
                for statement in policy_doc['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        least_priv_rating = 'failed_high'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        least_priv_rating = 'failed_low'

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if least_priv_rating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": role_arn + "/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": role_arn + "role_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {role_arn} inline policy {policy_name} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": role_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {
                                    "PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif least_priv_rating == 'failed_low':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": role_arn + "/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": role_arn + "role_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {role_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": role_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {
                                    "PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif least_priv_rating == 'failed_high':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": role_arn + "/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": role_arn + "role_policy_least_priv",
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {role_arn} inline policy {policy_name} is not following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": role_arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {
                                    "PolicyName": policy_name}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-3",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-17",
                                "NIST SP 800-53 AC-19",
                                "NIST SP 800-53 AC-20",
                                "NIST SP 800-53 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except:
        pass