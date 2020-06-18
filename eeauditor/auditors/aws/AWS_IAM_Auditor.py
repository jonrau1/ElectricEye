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
from check_register import CheckRegister

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
def iam_access_key_age_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    user = list_users(cache=cache)
    allUsers = user["Users"]
    for users in allUsers:
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccount
                            + ":product/"
                            + awsAccount
                            + "/default",
                            "GeneratorId": userArn + keyId,
                            "AwsAccountId": awsAccount,
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccount
                            + ":product/"
                            + awsAccount
                            + "/default",
                            "GeneratorId": userArn + keyId,
                            "AwsAccountId": awsAccount,
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
def user_permission_boundary_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    user = list_users(cache=cache)
    allUsers = user["Users"]
    for users in allUsers:
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
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccount
                + ":product/"
                + awsAccount
                + "/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccount,
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
    user = list_users(cache=cache)
    allUsers = user["Users"]
    for users in allUsers:
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
def user_inline_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
def user_direct_attached_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccount
                    + ":product/"
                    + awsAccount
                    + "/default",
                    "GeneratorId": userArn,
                    "AwsAccountId": awsAccount,
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
def cis_aws_foundation_benchmark_pw_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                "Id": awsAccount + "/cis-aws-foundations-benchmark-pw-policy-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccount
                + ":product/"
                + awsAccount
                + "/default",
                "GeneratorId": awsAccount + "iam-password-policy",
                "AwsAccountId": awsAccount,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard",
                "Description": "The IAM password policy for account "
                + awsAccount
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
                        "Id": "AWS::::Account:" + awsAccount,
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
                "Id": awsAccount + "/cis-aws-foundations-benchmark-pw-policy-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccount
                + ":product/"
                + awsAccount
                + "/default",
                "GeneratorId": awsAccount + "iam-password-policy",
                "AwsAccountId": awsAccount,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAM.6] The IAM password policy should meet or exceed the AWS CIS Foundations Benchmark standard",
                "Description": "The IAM password policy for account "
                + awsAccount
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
                        "Id": "AWS::::Account:" + awsAccount,
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
    try:
        response = iam.list_server_certificates()
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(response["ServerCertificateMetadataList"]) != "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccount + "/server-x509-certs-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccount
                + ":product/"
                + awsAccount
                + "/default",
                "GeneratorId": awsAccount + "server-cert",
                "AwsAccountId": awsAccount,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
                "Description": "There are server certificates stored in AWS IAM for the account "
                + awsAccount
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
                        "Id": "AWS::::Account:" + awsAccount,
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
                "Id": awsAccount + "/server-x509-certs-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccount
                + ":product/"
                + awsAccount
                + "/default",
                "GeneratorId": awsAccount + "server-cert",
                "AwsAccountId": awsAccount,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[IAM.7] There should not be any server certificates stored in AWS IAM",
                "Description": "There are not server certificates stored in AWS IAM for the account "
                + awsAccount
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
                        "Id": "AWS::::Account:" + awsAccount,
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
