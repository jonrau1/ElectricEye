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
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def global_region_generator(awsPartition):
    # Global Service Region override
    if awsPartition == "aws":
        globalRegion = "aws-global"
    elif awsPartition == "aws-us-gov":
        globalRegion = "aws-us-gov-global"
    elif awsPartition == "aws-cn":
        globalRegion = "aws-cn-global"
    elif awsPartition == "aws-iso":
        globalRegion = "aws-iso-global"
    elif awsPartition == "aws-isob":
        globalRegion = "aws-iso-b-global"
    elif awsPartition == "aws-isoe":
        globalRegion = "aws-iso-e-global"
    else:
        globalRegion = "aws-global"

    return globalRegion

def get_iam_users(cache, session):
    response = cache.get("get_iam_users")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_iam_users"] = iam.list_users(MaxItems=1000)["Users"]
    return cache["get_iam_users"]

def get_custom_policies(cache, session):
    response = cache.get("get_custom_policies")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_custom_policies"] = iam.list_policies(Scope="Local")["Policies"]
    return cache["get_custom_policies"]

def get_iam_groups(cache, session):
    response = cache.get("get_iam_groups")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_iam_groups"] = iam.list_groups()["Groups"]
    return cache["get_iam_groups"]

def get_iam_roles(cache, session):
    response = cache.get("get_iam_roles")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_iam_roles"] = iam.list_roles()["Roles"]
    return cache["get_iam_roles"]

def get_account_summary(cache, session):
    response = cache.get("get_account_summary")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_account_summary"] = iam.get_account_summary()["SummaryMap"]
    return cache["get_account_summary"]

def get_virtual_mfa(cache, session):
    response = cache.get("get_virtual_mfa")
    if response:
        return response
    
    iam = session.client("iam")

    cache["get_virtual_mfa"] = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
    return cache["get_virtual_mfa"]

@registry.register_check("iam")
def iam_access_key_age_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.1] IAM Access Keys should be rotated every 90 days"""
    iam = session.client("iam")
    todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in get_iam_users(cache, session):
        userName = users["UserName"]
        userArn = users["Arn"]
        # Get keys per User
        for keys in iam.list_access_keys(UserName=userName)["AccessKeyMetadata"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(keys,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            keyUserName = keys["UserName"]
            keyId = keys["AccessKeyId"]
            keyArn = f"arn:{awsPartition}:iam::{awsAccountId}:user/{keyUserName}/access-key/{keyId}"
            keyStatus = keys["Status"]
            # If there is an active key, see if it has been rotated in the last 90
            if keyStatus == "Active":
                keyCreateDate = keys["CreateDate"]
                keyAgeFinder = todaysDatetime - keyCreateDate
                if keyAgeFinder <= datetime.timedelta(days=90):
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{keyArn}/iam-access-key-age-check",
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Access Key"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamAccessKey",
                                "Id": keyArn,
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
                                "MITRE ATT&CK T1586",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.14"
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
                        "Id": f"{keyArn}/iam-access-key-age-check",
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Access Key"
                        },
                        "Resources": [
                            {
                                "Type": "AwsIamAccessKey",
                                "Id": keyArn,
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
                                "MITRE ATT&CK T1586",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.14"
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
    for users in get_iam_users(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(users,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        userName = users["UserName"]
        userArn = users["Arn"]
        try:
            # this value isn"t actually going to be used - we need to check if it there
            users["PermissionsBoundary"]["PermissionsBoundaryArn"]
            hasPermBoundary = True
        except KeyError:
            hasPermBoundary = False
        # this is a passing check
        if hasPermBoundary is True:
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4"
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4"
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
    for users in get_iam_users(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(users,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        userName = users["UserName"]
        userArn = users["Arn"]
        # check if the user has a password - override MFA passing if not
        if "PasswordLastUsed" not in users:
            passwordMfaPassing = True
        else:
            if not iam.list_mfa_devices(UserName=userName)["MFADevices"]:
                passwordMfaPassing = False
            else:
                passwordMfaPassing = True

        if passwordMfaPassing is False:
        # this is a failing check
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
                "Title": "[IAM.3] IAM users with passwords should have Multi-Factor Authentication (MFA) enabled",
                "Description": f"IAM user {userName} does not have MFA enabled. For increased security, AWS recommends that you configure multi-factor authentication (MFA) to help protect your AWS resources. Passwords are the most common method of authenticating a sign-in to a computer or online service, but they're also the most vulnerable. People can choose easy passwords and use the same passwords for multiple sign-ins to different computers and services. To provide an extra level of security for sign-ins, you must use multifactor authentication (MFA), which uses both a password, which should be strong, and an additional verification method based on either something you have with you that isn't easily duplicated, such as Time-based One Time Password (TOTP) generation application such as Google Authenticator or using a FIDO2 hardware key such as a Yubikey. The additional verification method isn't employed until after the user's password has been verified. With MFA, even if a strong user password is compromised, the attacker doesn't have your smart phone or your fingerprint to complete the sign-in. Refer to the remediation section if this behavior is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                        "ISO 27001:2013 A.9.4.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 1.10"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
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
                "Title": "[IAM.3] IAM users with passwords should have Multi-Factor Authentication (MFA) enabled",
                "Description": f"IAM user {userName} has MFA enabled or does not have a password.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on MFA refer to the Using Multi-Factor Authentication (MFA) in AWS section of the AWS IAM User Guide",
                        "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                        "ISO 27001:2013 A.9.4.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 1.10",
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
    for users in get_iam_users(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(users,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        userName = users["UserName"]
        userArn = users["Arn"]
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
    for users in get_iam_users(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(users,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        userName = users["UserName"]
        userArn = users["Arn"]
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS IAM",
                    "AssetComponent": "User"
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
    response = iam.get_account_password_policy()
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(response,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # Sometimes, PW Policy attributes are missing which would make it a fail - different than the error of it not being enabled at all
    try:
        pwPolicy = response["PasswordPolicy"]
        minPwLength = pwPolicy["MinimumPasswordLength"]
        symbolReq = pwPolicy["RequireSymbols"]
        numberReq = pwPolicy["RequireNumbers"]
        uppercaseReq = pwPolicy["RequireUppercaseCharacters"]
        lowercaseReq = pwPolicy["RequireLowercaseCharacters"]
        maxPwAge = pwPolicy["MaxPasswordAge"]
        pwReuse = pwPolicy["PasswordReusePrevention"]

        if (
            minPwLength >= 14
            and maxPwAge <= 90
            and pwReuse >= 24
            and symbolReq is True
            and numberReq is True
            and uppercaseReq is True
            and lowercaseReq is True
        ):
            cisCompliantPolicy = True
        else:
            cisCompliantPolicy = False
    except KeyError:
        print("IAM Password Policy is missing one or more attributes, this is a failing check.")
        cisCompliantPolicy = False
    except botocore.exceptions.ClientError as error:
        # Handle "NoSuchEntity" exception which means the PW policy does not exist
        if error.response["Error"]["Code"] == "NoSuchEntity":
            cisCompliantPolicy = False
            assetB64 = None
    
    if cisCompliantPolicy is True:
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
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Password Policy"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/Password_Policy",
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.8",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.9"
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
            "Description": f"The IAM password policy for account {awsAccountId} does not meet the AWS CIS Foundations Benchmark V1.2 standard or is not defined at all. The V1.5 Benchmark still expects a length of 14 or greater and reuse prevention. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on the CIS AWS Foundations Benchmark standard for the password policy refer to the linked Standard",
                    "Url": "https://d1.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Password Policy"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/Password_Policy",
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.8",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.9"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("iam")
def aws_iam_server_certifcates_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.7] There should not be any server certificates stored in AWS IAM"""
    iam = session.client("iam")
    serverCertArn = f"arn:{awsPartition}:iam::{awsAccountId}:server-certificate/*"
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # use a list comprehension to find any server certs in IAM
    # this is a failing check
    if iam.list_server_certificates()["ServerCertificateMetadataList"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(iam.list_server_certificates(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{serverCertArn}/server-x509-certs-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{serverCertArn}/server-x509-certs-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
            "Description": f"There are server certificates stored in AWS IAM for the account {awsAccountId}. ACM is the preferred tool to provision, manage, and deploy your server certificates. With ACM you can request a certificate or deploy an existing ACM or external certificate to AWS resources. Certificates provided by ACM are free and automatically renew. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on server certificates refer to the Working with Server Certificates section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Server Certificate"
            },
            "Resources": [
                {
                    "Type": "AwsIamServerCertificate",
                    "Id": serverCertArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.19"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        # B64 encode all of the details for the Asset
        assetB64 = None
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{serverCertArn}/server-x509-certs-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{serverCertArn}/server-x509-certs-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
            "Description": f"There are not server certificates stored in AWS IAM for the account {awsAccountId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on server certificates refer to the Working with Server Certificates section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Server Certificate"
            },
            "Resources": [
                {
                    "Type": "AwsIamServerCertificate",
                    "Id": serverCertArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.19"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("iam")
def iam_created_managed_policy_least_priv_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.8] Managed policies should follow least privilege principles"""
    iam = session.client("iam")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        for mpolicy in get_custom_policies(cache, session):
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(mpolicy,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            policyArn = mpolicy["Arn"]
            versionId = mpolicy["DefaultVersionId"]
            policyDocument = iam.get_policy_version(
                PolicyArn=policyArn,
                VersionId=versionId
            )["PolicyVersion"]["Document"]
            #handle policies docs returned as strings
            if type(policyDocument) == str:
                policyDocument = json.loads(policyDocument)

            leastPrivilegeRating = "passing"
            for statement in policyDocument["Statement"]:
                if statement["Effect"] == "Allow":
                    if statement.get("Condition") == None: 
                        # action structure could be a string or a list
                        if type(statement["Action"]) == list: 
                            if len(["True" for x in statement["Action"] if ":*" in x or "*" == x]) > 0:
                                if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                    leastPrivilegeRating = "failedHigh"
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement["Resource"]) == list: 
                                    leastPrivilegeRating = "failedLow"

                        # Single action in a statement
                        elif type(statement["Action"]) == str:
                            if ":*" in statement["Action"] or statement["Action"] == "*":
                                if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                    leastPrivilegeRating = "failedHigh"
                                    # Means that an initial failure will not be overwritten by a lower finding later
                                    next
                                elif type(statement["Resource"]) == list: 
                                    leastPrivilegeRating = "failedLow"
            if leastPrivilegeRating == "passing":
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
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetComponent": "Policy"
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            elif leastPrivilegeRating == "failedLow":
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
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetComponent": "Policy"
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            elif leastPrivilegeRating == "failedHigh":
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
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetComponent": "Policy"
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
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
        for users in get_iam_users(cache, session):
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(users,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            userArn = users["Arn"]
            userName = users["UserName"]

            policyNames = iam.list_user_policies(
                UserName=userName
            )["PolicyNames"]
            for policyName in policyNames:
                policyDocument = iam.get_user_policy(
                    UserName=userName,
                    PolicyName=policyName
                )["PolicyDocument"]

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = "passing"
                for statement in policyDocument["Statement"]:
                    if statement["Effect"] == "Allow":
                        if statement.get("Condition") == None: 
                            # action structure could be a string or a list
                            if type(statement["Action"]) == list: 
                                if len(["True" for x in statement["Action"] if ":*" in x or "*" == x]) > 0:
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"

                            # Single action in a statement
                            elif type(statement["Action"]) == str:
                                if ":*" in statement["Action"] or statement["Action"] == "*":
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if leastPrivilegeRating == "passing":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "User"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedLow":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "User"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedHigh":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "User"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
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
        for group in get_iam_groups(cache, session):
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(group,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            groupArn = group["Arn"]
            groupName = group["GroupName"]

            policyNames = iam.list_group_policies(
                GroupName=groupName
            )["PolicyNames"]
            for policyName in policyNames:
                policyDocument = iam.get_group_policy(
                    GroupName=groupName,
                    PolicyName=policyName
                )["PolicyDocument"]

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = "passing"
                for statement in policyDocument["Statement"]:
                    if statement["Effect"] == "Allow":
                        if statement.get("Condition") == None: 
                            # action structure could be a string or a list
                            if type(statement["Action"]) == list: 
                                if len(["True" for x in statement["Action"] if ":*" in x or "*" == x]) > 0:
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"

                            # Single action in a statement
                            elif type(statement["Action"]) == str:
                                if ":*" in statement["Action"] or statement["Action"] == "*":
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"

                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                if leastPrivilegeRating == "passing":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Group"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedLow":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Group"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedHigh":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Group"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
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
        for role in get_iam_roles(cache, session):
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(role,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            roleArn = role["Arn"]
            roleName = role["RoleName"]

            policyNames = iam.list_role_policies(
                RoleName=roleName
            )["PolicyNames"]
            for policyName in policyNames:
                policyDocument = iam.get_role_policy(
                    RoleName=roleName,
                    PolicyName=policyName
                )["PolicyDocument"]

                #handle policies docs returned as strings
                if type(policyDocument) == str:
                    policyDocument = json.loads(policyDocument)

                leastPrivilegeRating = "passing"
                for statement in policyDocument["Statement"]:
                    if statement["Effect"] == "Allow":
                        if statement.get("Condition") == None: 
                            # action structure could be a string or a list
                            if type(statement["Action"]) == list: 
                                if len(["True" for x in statement["Action"] if ":*" in x or "*" == x]) > 0:
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"

                            # Single action in a statement
                            elif type(statement["Action"]) == str:
                                if ":*" in statement["Action"] or statement["Action"] == "*":
                                    if type(statement["Resource"]) == str and statement["Resource"] == "*":
                                        leastPrivilegeRating = "failedHigh"
                                        # Means that an initial failure will not be overwritten by a lower finding later
                                        next
                                    elif type(statement["Resource"]) == list: 
                                        leastPrivilegeRating = "failedLow"
                
                if leastPrivilegeRating == "passing":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Role"
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
                                "ISO 27001:2013 A.13.2.1",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedLow":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Role"
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
                                "ISO 27001:2013 A.13.2.1",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif leastPrivilegeRating == "failedHigh":
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
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": global_region_generator(awsPartition),
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS IAM",
                            "AssetComponent": "Role"
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
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "AICPA TSC CC6.3",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "CIS Amazon Web Services Foundations Benchmark V1.5 1.16"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
    except Exception as e:
        print(e)
        pass

@registry.register_check("iam")
def aws_iam_root_user_access_keys_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.12] The AWS Root User should not have any IAM access keys"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    rootUserArn = f"arn:aws:iam::{awsAccountId}:root"
    if get_account_summary(cache, session)["AccountAccessKeysPresent"] != 0:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-access-key-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-access-key-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[IAM.12] The AWS Root User should not have any IAM access keys",
            "Description": f"The IAM Root user for Account {awsAccountId} has IAM access keys assigned to it. When you first create an Amazon Web Services (AWS) account, you begin with a single sign-in identity that has complete access to all AWS services and resources in the account. This identity is called the AWS account root user and is accessed by signing in with the email address and password that you used to create the account. AWS strongly recommends that you do not use the root user for your everyday tasks, even the administrative ones. As a best practice, safeguard your root user credentials and don't use them for everyday tasks. Root user credentials are only used to perform a few account and service management tasks. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on removing Root User access keys refer to the Deleting access keys for the root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_delete-key"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.4"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-access-key-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-access-key-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.12] The AWS Root User should not have any IAM access keys",
            "Description": f"The IAM Root user for Account {awsAccountId} does not have IAM access keys assigned to it.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on removing Root User access keys refer to the Deleting access keys for the root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_delete-key"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("iam")
def aws_iam_root_user_mfa_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.13] The AWS Root User should have a multi-factor authentication (MFA) device registered"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    rootUserArn = f"arn:aws:iam::{awsAccountId}:root"
    if get_account_summary(cache, session)["AccountMFAEnabled"] == 0:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-mfa-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-mfa-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[IAM.13] The AWS Root User should have a multi-factor authentication (MFA) device registered",
            "Description": f"The IAM Root user for Account {awsAccountId} does not have an MFA device registered. When you first create an Amazon Web Services (AWS) account, you begin with a single sign-in identity that has complete access to all AWS services and resources in the account. This identity is called the AWS account root user and is accessed by signing in with the email address and password that you used to create the account. AWS strongly recommends that you do not use the root user for your everyday tasks, even the administrative ones. AWS recommend's that you follow the security best practice to enable multi-factor authentication (MFA) for your account. Because your root user can perform sensitive operations in your account, adding an additional layer of authentication helps you to better secure your account. Multiple types of MFA are available. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on registering MFA devices for your Root User refer to the Enable MFA on the AWS account root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-mfa-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-mfa-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.13] The AWS Root User should have a multi-factor authentication (MFA) device registered",
            "Description": f"The IAM Root user for Account {awsAccountId} does have an MFA device registered.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on registering MFA devices for your Root User refer to the Enable MFA on the AWS account root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("iam")
def aws_iam_root_user_mfa_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.14] The AWS Root User should use a hardware multi-factor authentication (MFA) device"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    rootUserArn = f"arn:aws:iam::{awsAccountId}:root"
    if get_account_summary(cache, session)["AccountMFAEnabled"] == 0:
        rootHardwareMfa = False
    else:
        # Use a list comprehension to get the root user, if this list has contents it means the Root User has a Virtual MFA Device and not Hardware
        rootVirtualMfa = [user["User"]["Arn"] for user in get_virtual_mfa(cache, session) if user["User"]["Arn"] == rootUserArn]
        if rootVirtualMfa:
            rootHardwareMfa = False
        else:
            rootHardwareMfa = True

    if rootHardwareMfa is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-hardware-mfa-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-hardware-mfa-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[IAM.14] The AWS Root User should use a hardware multi-factor authentication (MFA) device",
            "Description": f"The IAM Root user for Account {awsAccountId} does not have a hardware MFA device registered. When you first create an Amazon Web Services (AWS) account, you begin with a single sign-in identity that has complete access to all AWS services and resources in the account. This identity is called the AWS account root user and is accessed by signing in with the email address and password that you used to create the account. AWS strongly recommends that you do not use the root user for your everyday tasks, even the administrative ones. AWS recommend's that you follow the security best practice to enable multi-factor authentication (MFA) for your account. Because your root user can perform sensitive operations in your account, adding an additional layer of authentication helps you to better secure your account. Multiple types of MFA are available. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on registering MFA devices for your Root User refer to the Enable MFA on the AWS account root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.6"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-iam-hardware-mfa-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-iam-hardware-mfa-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.14] The AWS Root User should use a hardware multi-factor authentication (MFA) device",
            "Description": f"The IAM Root user for Account {awsAccountId} does have a hardware MFA device registered.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on registering MFA devices for your Root User refer to the Enable MFA on the AWS account root user section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
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
                    "MITRE ATT&CK T1586",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.6"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("iam")
def iam_access_key_unused_fortyfive_days_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.15] AWS IAM Access Keys that have not been used in the last 45 days should be disabled"""
    iam = session.client("iam")
    todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
    fortyFiveDayDelta = datetime.timedelta(days=45)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for users in get_iam_users(cache, session):
        userName = users["UserName"]
        # Get keys per User
        for keys in iam.list_access_keys(UserName=userName)["AccessKeyMetadata"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(keys,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            keyUserName = keys["UserName"]
            keyId = keys["AccessKeyId"]
            keyArn = f"arn:{awsPartition}:iam::{awsAccountId}:user/{keyUserName}/access-key/{keyId}"
            lastUsed = iam.get_access_key_last_used(AccessKeyId=keyId)["AccessKeyLastUsed"]
            if "LastUsedDate" not in lastUsed or lastUsed["LastUsedDate"] < (todaysDatetime - fortyFiveDayDelta):
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{keyArn}/iam-access-key-rotated-unused-forty-five-days-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{keyArn}/iam-access-key-rotated-unused-forty-five-days-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[IAM.15] AWS IAM Access Keys that have not been used in the last 45 days should be disabled",
                    "Description": f"IAM access key {keyId} for user {keyUserName} has not been used in the last 45 days. As a security best practice, AWS recommends that you regularly rotate (change) IAM user access keys. Regularly rotating long-term credentials helps you familiarize yourself with the process. This is useful in case you are ever in a situation where you must rotate credentials, such as when an employee leaves your company. If your administrator granted you the necessary permissions, you can rotate your own access keys. Refer to the remediation section if this behavior is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetComponent": "Access Key"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": keyArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamAccessKey": {
                                    "PrincipalId": keyId,
                                    "PrincipalName": keyUserName
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
                            "MITRE ATT&CK T1586",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 1.12"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{keyArn}/iam-access-key-rotated-unused-forty-five-days-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{keyArn}/iam-access-key-rotated-unused-forty-five-days-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[IAM.15] AWS IAM Access Keys that have not been used in the last 45 days should be disabled",
                    "Description": f"IAM access key {keyId} for user {keyUserName} has been used in the last 45 days, ensure they are rotated as soon as your policy dictates or as soon as you are able.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IAM access key rotation refer to the Rotating Access Keys section of the AWS IAM User Guide",
                            "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS IAM",
                        "AssetComponent": "Access Key"
                    },
                    "Resources": [
                        {
                            "Type": "AwsIamAccessKey",
                            "Id": keyArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsIamAccessKey": {
                                    "PrincipalId": keyId,
                                    "PrincipalName": keyUserName
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
                            "MITRE ATT&CK T1586",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 1.12"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("iam")
def aws_iam_root_user_usage_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.16] The AWS Root User should not be used for day-to-day activities"""
    cloudtrail = session.client("cloudtrail")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    rootUserArn = f"arn:aws:iam::{awsAccountId}:root"
    # Set time span for CloudTrail LookupEvents API - it can only look back 90 days
    endTime = datetime.datetime.utcnow()
    startTime = endTime - datetime.timedelta(days=89)
    events = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "Username",
                "AttributeValue": "root"
            }
        ],
        StartTime=startTime,
        EndTime=endTime
    )["Events"]

    # this is a failing check
    if events:
        # use a list-from-dict comprehension to record all unique IAM Actions for the root user
        uniqueRootIamActions = list({event["EventName"] for event in events})
        uniqueRootIamActionsSentence = ", ".join(str(item) for item in uniqueRootIamActions)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-usage-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-usage-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[IAM.16] The AWS Root User should not be used for day-to-day activities",
            "Description": f"The IAM Root user for Account {awsAccountId} has been used in the last 90 days and should be audited to ensure it is not used for day-to-day activities. When you create an AWS account you establish a root user name and password to sign in to the AWS Management Console. Safeguard your root user credentials the same way you would protect other sensitive personal information. You can do this by configuring MFA for your root user credentials. Do not use your root user for everyday tasks. Use the root user to complete the tasks that only the root user can perform. The root user used the following APIs in the last 90 days: {uniqueRootIamActionsSentence}. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for your Root User refer to the Security best practices in IAM section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
                        }
                    }
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.7"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{rootUserArn}/root-user-usage-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{rootUserArn}/root-user-usage-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.16] The AWS Root User should not be used for day-to-day activities",
            "Description": f"The IAM Root user for Account {awsAccountId} has not been used in the last 90 days.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for your Root User refer to the Security best practices in IAM section of the AWS IAM User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": None,
                "AssetClass": "Identity & Access Management",
                "AssetService": "AWS IAM",
                "AssetComponent": "Root User"
            },
            "Resources": [
                {
                    "Type": "AwsIamUser",
                    "Id": rootUserArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsIamUser": {
                            "UserName": "root"
                        }
                    }
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.7"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("access-analyzer")
def aws_iam_access_analyzer_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[IAM.17] AWS IAM Access Analyzer should be enabled"""
    accessanalyzer = session.client("accessanalyzer")
    response = accessanalyzer.list_analyzers()
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(response,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    if not response["analyzers"]:
        analyzerArn = f"arn:{awsPartition}:access-analyzer:{awsRegion}:{awsAccountId}:analyzer"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{analyzerArn}/security-services-iaa-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{analyzerArn}/security-services-iaa-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[IAM.17] AWS IAM Access Analyzer should be enabled",
            "Description": f"Amazon IAM Access Analyzer is not enabled in {awsRegion}. AWS IAM Access Analyzer is a fully managed security service that helps you identify and prevent unintended public and cross-account access to your AWS resources. By using Access Analyzer, you can quickly and easily analyze your policies, identify potential security issues, and take action to remediate them. Access Analyzer provides actionable recommendations and visualizations of access paths, making it easy to understand how access is granted and identify any unintended access. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling",
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
                "AssetService": "AWS IAM Access Analyzer",
                "AssetComponent": "Account Activation"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": analyzerArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.20"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        analyzerArn = response["analyzers"][0]["arn"]
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{analyzerArn}/security-services-iaa-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{analyzerArn}/security-services-iaa-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[IAM.17] AWS IAM Access Analyzer should be enabled",
            "Description": f"Amazon IAM Access Analyzer is enabled in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling",
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
                "AssetService": "AWS IAM Access Analyzer",
                "AssetComponent": "Account Activation"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": analyzerArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "CIS Amazon Web Services Foundations Benchmark V1.5 1.20"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## EOF