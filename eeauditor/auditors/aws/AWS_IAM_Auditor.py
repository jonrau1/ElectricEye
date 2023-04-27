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

import botocore.exceptions
import datetime
import json
from check_register import CheckRegister

registry = CheckRegister()

def list_users(cache, session):
    iam = session.client("iam")
    response = cache.get("list_users")
    if response:
        return response
    cache["list_users"] = iam.list_users(MaxItems=1000)
    return cache["list_users"]

@registry.register_check("iam")
def iam_access_key_age_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.1] IAM Access Keys should be rotated every 90 days"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in list_users(cache, session)["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # Get keys per User
        response = iam.list_access_keys(UserName=userName)
        for keys in response["AccessKeyMetadata"]:
            keyUserName = str(keys["UserName"])
            keyId = str(keys["AccessKeyId"])
            keyStatus = str(keys["Status"])
            # If there is an active key, see if it has been rotated in the last 90
            if keyStatus == "Active":
                keyCreateDate = keys["CreateDate"]
                todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
                keyAgeFinder = todaysDatetime - keyCreateDate
                if keyAgeFinder <= datetime.timedelta(days=90):
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{keyUserName}{keyId}/iam-access-key-age-check",
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
                        "Description": f"IAM access key {keyId} for user {keyUserName} is not over 90 days old.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Access Key"
                        },
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
                                        "Status": keyStatus
                                    }
                                }
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
                                "MITRE ATT&CK T1589",
                                "MITRE ATT&CK T1586"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
                else:
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{keyUserName}{keyId}/iam-access-key-age-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": userArn + keyId,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[IAM.1] IAM Access Keys should be rotated every 90 days",
                        "Description": f"IAM access key {keyId} for user {keyUserName} is over 90 days old. As a security best practice, AWS recommends that you regularly rotate (change) IAM user access keys. If your administrator granted you the necessary permissions, you can rotate your own access keys. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Access Key"
                        },
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
                                        "Status": keyStatus
                                    }
                                }
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
                                "MITRE ATT&CK T1589",
                                "MITRE ATT&CK T1586"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
            # skip Inactive keys
            else:
                continue

@registry.register_check("iam")
def user_permission_boundary_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.2] IAM users should have permissions boundaries attached"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in list_users(cache, session)["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        try:
            # this value isn't actually going to be used - we need to check if it there
            users["PermissionsBoundary"]["PermissionsBoundaryArn"]
            hasPermBoundary = True
        except KeyError:
            hasPermBoundary = False
        # this is a passing check
        if hasPermBoundary == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-permissions-boundary-check",
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
                "Description": f"IAM user {userName} has a permissions boundary attached.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on permissions boundaries refer to the Permissions Boundaries for IAM Entities section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        # this is a failing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-permissions-boundary-check",
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
                "Description": f"IAM user {userName} does not have a permissions boundary attached. A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity. A permissions boundary allows it to perform only the actions that are allowed by both its identity-based policies and its permissions boundaries. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on permissions boundaries refer to the Permissions Boundaries for IAM Entities section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("iam")
def user_mfa_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.3] IAM users with passwords should have Multi-Factor Authentication (MFA) enabled"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in list_users(cache, session)["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # check if the user has a password
        try:
            users["PasswordLastUsed"]
            pwCheck = True
        except KeyError:
            pwCheck = False
        # If there is a password, evaluate if there any MFA devices
        if pwCheck == True:
            # this is a failing check due to the list comprehension returning empty (false)
            if not iam.list_mfa_devices(UserName=userName)["MFADevices"]:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{userArn}/iam-user-mfa-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[IAM.3] IAM users should have Multi-Factor Authentication (MFA) enabled",
                    "Description": f"IAM user {userName} does not have MFA enabled. For increased security, AWS recommends that you configure multi-factor authentication (MFA) to help protect your AWS resources. Refer to the remediation section if this behavior is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetType": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamUser": {
                                    "UserName": userName
                                }
                            }
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
                            "ISO 27001:2013 A.9.4.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            # this is passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{userArn}/iam-user-mfa-check",
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
                    "Description": f"IAM user {userName} has MFA enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetType": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamUser": {
                                    "UserName": userName
                                }
                            }
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
                            "ISO 27001:2013 A.9.4.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        # this user does not have a password, but will pass by default anyway
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-mfa-check",
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
                "Description": f"IAM user {userName} does not have a password and does not need MFA enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("iam")
def user_inline_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.4] IAM users should not have attached in-line policies"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in list_users(cache, session)["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # use a list comprehension to check if there are any inline policies
        # this is a failing check
        if iam.list_user_policies(UserName=userName)["PolicyNames"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-attach-inline-check",
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
                "Description": f"IAM user {userName} has an in-line policy attached. It is recommended that IAM policies be applied directly to groups and roles but not users. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-attach-inline-check",
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
                "Description": "IAM user {userName} does not have an in-line policy attached.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("iam")
def user_direct_attached_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.5] IAM users should not have attached managed policies"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in list_users(cache, session)["Users"]:
        userName = str(users["UserName"])
        userArn = str(users["Arn"])
        # use a list comprehension to check if there are any attached managed policies
        # this is a failing check
        if iam.list_attached_user_policies(UserName=userName)["AttachedPolicies"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-attach-managed-policy-check",
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
                "Description": f"IAM user {userName} has a managed policy attached. It is recommended that IAM policies be applied directly to groups and roles but not users. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userArn}/iam-user-attach-managed-policy-check",
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
                "Description": f"IAM user {userName} does not have a managed policy attached.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on user attached policies refer to the Managed Policies and Inline Policies section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "User"
                },
                "Resources": [
                    {
                        "Type": "AwsIamUser",
                        "Id": userArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsIamUser": {
                                "UserName": userName
                            }
                        }
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("iam")
def cis_aws_foundation_benchmark_pw_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        response = iam.get_account_password_policy()
        pwPolicy = response["PasswordPolicy"]
        minPwLength = int(pwPolicy["MinimumPasswordLength"])
        symbolReq = str(pwPolicy["RequireSymbols"])
        numberReq = str(pwPolicy["RequireNumbers"])
        uppercaseReq = str(pwPolicy["RequireUppercaseCharacters"])
        lowercaseReq = str(pwPolicy["RequireLowercaseCharacters"])
        maxPwAge = int(pwPolicy["MaxPasswordAge"])
        pwReuse = int(pwPolicy["PasswordReusePrevention"])
        
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "Password Policy"
                },
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "Password Policy"
                },
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
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
    # this is a failing check
    except botocore.exceptions.ClientError as error:
        # Handle "NoSuchEntity" exception which means the PW policy does not exist
        if error.response['Error']['Code'] == 'NoSuchEntity':
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
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard",
                "Description": "The IAM password policy for account "
                + awsAccountId
                + " was not found! Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on the CIS AWS Foundations Benchmark standard for the password policy refer to the linked Standard",
                        "Url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetType": "Password Policy"
                },
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

@registry.register_check("iam")
def server_certs_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.7] There should not be any server certificates stored in AWS IAM"""
    iam = session.client("iam")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # use a list comprehension to find any server certs in IAM
    # this is a failing check
    if iam.list_server_certificates()["ServerCertificateMetadataList"]:
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
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetType": "Server Certificate Storage"
            },
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
    # this is a passing check
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
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetType": "Server Certificate Storage"
            },
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

@registry.register_check("iam")
def iam_created_managed_policy_least_priv_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.8] Managed policies should follow least privilege principles"""
    iam = session.client("iam")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        for mpolicy in iam.list_policies(Scope='Local')['Policies']:
            policyArn = mpolicy['Arn']
            versionId = mpolicy['DefaultVersionId']
            policyDocument = iam.get_policy_version(
                PolicyArn=policyArn,
                VersionId=versionId
            )['PolicyVersion']['Document']
            #handle policies docs returned as strings
            if type(policyDocument) == str:
                policyDocument = json.loads(policyDocument)

            leastPrivilegeRating = 'passing'
            for statement in policyDocument['Statement']:
                if statement["Effect"] == 'Allow':
                    if statement.get('Condition') == None: 
                        # action structure could be a string or a list
                        if type(statement['Action']) == list: 
                            if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                if type(statement['Resource']) == str and statement['Resource'] == '*':
                                    leastPrivilegeRating = 'failedHigh'
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement['Resource']) == list: 
                                    leastPrivilegeRating = 'failedLow'

                        # Single action in a statement
                        elif type(statement['Action']) == str:
                            if ":*" in statement['Action'] or statement['Action'] == '*':
                                if type(statement['Resource']) == str and statement['Resource'] == '*':
                                    leastPrivilegeRating = 'failedHigh'
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement['Resource']) == list: 
                                    leastPrivilegeRating = 'failedLow'
            if leastPrivilegeRating == 'passing':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{policyArn}/mpolicy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policyArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policyArn} is following least privilege principles.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetType": "Policy"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policyArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamPolicy": {
                                    "DefaultVersionId": versionId
                                }
                            }
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
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            elif leastPrivilegeRating == 'failedLow':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{policyArn}/mpolicy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policyArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policyArn} is not following least privilege principles and has been rated: {leastPrivilegeRating}. Refer to the remediation section if this behavior is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetType": "Policy"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policyArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamPolicy": {
                                    "DefaultVersionId": versionId
                                }
                            }
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
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            elif leastPrivilegeRating == 'failedHigh':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{policyArn}/mpolicy_least_priv",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": policyArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[IAM.8] Managed policies should follow least privilege principles",
                    "Description": f"The customer managed policy {policyArn} is not following least privilege principles and has been rated: {leastPrivilegeRating}. Refer to the remediation section if this behavior is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM least privilege refer to the Controlling access section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetType": "Policy"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamPolicy",
                            "Id": policyArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamPolicy": {
                                    "DefaultVersionId": versionId
                                }
                            }
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
                            "ISO 27001:2013 A.13.2.1"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
    except Exception as e:
        print(e)
        pass

@registry.register_check("iam")
def iam_user_policy_least_priv_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.9] User inline policies should follow least privilege principles"""
    iam = session.client("iam")
    try:
        for users in list_users(cache, session)["Users"]:
            userArn = users['Arn']
            userName = users['UserName']

            policyNames = iam.list_user_policies(
                UserName=userName
            )['PolicyNames']
            for policyName in policyNames:
                policyDocument = iam.get_user_policy(
                    UserName=userName,
                    PolicyName=policyName
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = 'passing'
                for statement in policyDocument['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if leastPrivilegeRating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{userArn}/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {userArn} inline policy {policyName} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamUser",
                                "Id": userArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamUser": {
                                        "UserPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "UserName": userName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedLow':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{userArn}/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {userArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamUser",
                                "Id": userArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamUser": {
                                        "UserPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "UserName": userName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedHigh':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{userArn}/user_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.9] User inline policies should follow least privilege principles",
                        "Description": f"The user {userArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamUser",
                                "Id": userArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamUser": {
                                        "UserPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "UserName": userName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except Exception as e:
        print(e)
        pass

@registry.register_check("iam")
def iam_group_policy_least_priv_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.10] Group inline policies should follow least privilege principles"""
    iam = session.client("iam")
    try:
        Groups = iam.list_groups()
        for group in Groups['Groups']:
            groupArn = group['Arn']
            groupName = group['GroupName']

            policyNames = iam.list_group_policies(
                GroupName=groupName
            )['PolicyNames']
            for policyName in policyNames:
                policyDocument = iam.get_group_policy(
                    GroupName=groupName,
                    PolicyName=policyName
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = 'passing'
                for statement in policyDocument['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if leastPrivilegeRating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{groupArn}/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": groupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {groupArn} inline policy {policyName} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Group"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": groupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamGroup": {
                                        "GroupPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "GroupName": groupName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedLow':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{groupArn}/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": groupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {groupArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Group"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": groupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamGroup": {
                                        "GroupPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "GroupName": groupName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedHigh':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{groupArn}/group_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": groupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.10] Group inline policies should follow least privilege principles",
                        "Description": f"The group {groupArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Group"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamGroup",
                                "Id": groupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamGroup": {
                                        "GroupPolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "GroupName": groupName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except Exception as e:
        print(e)
        pass

@registry.register_check("iam")
def iam_role_policy_least_priv_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.11] Role inline policies should follow least privilege principles"""
    iam = session.client("iam")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        Roles = iam.list_roles()
        for role in Roles['Roles']:
            roleArn = role['Arn']
            roleName = role['RoleName']

            policyNames = iam.list_role_policies(
                RoleName=roleName
            )['PolicyNames']
            for policyName in policyNames:
                policyDocument = iam.get_role_policy(
                    RoleName=roleName,
                    PolicyName=policyName
                )['PolicyDocument']

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = 'passing'
                for statement in policyDocument['Statement']:
                    if statement["Effect"] == 'Allow':
                        if statement.get('Condition') == None: 
                            # action structure could be a string or a list
                            if type(statement['Action']) == list: 
                                if len(['True' for x in statement['Action'] if ":*" in x or '*' == x]) > 0:
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'

                            # Single action in a statement
                            elif type(statement['Action']) == str:
                                if ":*" in statement['Action'] or statement['Action'] == '*':
                                    if type(statement['Resource']) == str and statement['Resource'] == '*':
                                        leastPrivilegeRating = 'failedHigh'
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement['Resource']) == list: 
                                        leastPrivilegeRating = 'failedLow'
                
                if leastPrivilegeRating == 'passing':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{roleArn}/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": roleArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {roleArn} inline policy {policyName} is following least privilege principles.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Role"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": roleArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamRole": {
                                        "RolePolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "RoleName": roleName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedLow':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{roleArn}/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": roleArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {roleArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Role"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": roleArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamRole": {
                                        "RolePolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "RoleName": roleName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == 'failedHigh':
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{roleArn}/role_policy_least_priv",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": roleArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[IAM.11] Role inline policies should follow least privilege principles",
                        "Description": f"The role {roleArn} inline policy {policyName} is not following least privilege principles. Refer to the remediation section if this behavior is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on IAM least privilege refer to the inline policy section of the AWS IAM User Guide",
                                "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html#inline-policies",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetType": "Role"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamRole",
                                "Id": roleArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsIamRole": {
                                        "RolePolicyList": [
                                            {
                                                "PolicyName": policyName
                                            }
                                        ],
                                        "RoleName": roleName
                                    }
                                }
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
                                "ISO 27001:2013 A.13.2.1"
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except Exception as e:
        print(e)
        pass