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
appstream = boto3.client("appstream")


def describe_users(cache):
    response = cache.get("describe_users")
    if response:
        return response
    cache["describe_users"] = appstream.describe_users(AuthenticationType="USERPOOL")
    return cache["describe_users"]


@registry.register_check("appstream")
def default_internet_access_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through AppStream 2.0 fleets
    response = appstream.describe_fleets()
    myAppstreamFleets = response["Fleets"]
    for fleet in myAppstreamFleets:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        fleetArn = str(fleet["Arn"])
        fleetName = str(fleet["DisplayName"])
        # find fleets that are configured to provide default internet access
        defaultInternetAccessCheck = str(fleet["EnableDefaultInternetAccess"])
        if defaultInternetAccessCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": fleetArn + "/appstream-default-internet-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": fleetArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[AppStream.1] AppStream 2.0 fleets should not provide default internet access",
                "Description": "AppStream 2.0 fleet "
                + fleetName
                + " is configured to provide default internet access. If you use the Default Internet Access option for enabling internet access, the NAT configuration is not limited to 100 fleet instances. If your deployment must support more than 100 concurrent users, use this configuration. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your fleet should not have default internet access refer to the instructions in the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAppStreamFleet",
                        "Id": fleetArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"fleetName": fleetName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            # create Sec Hub finding
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": fleetArn + "/appstream-default-internet-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": fleetArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[AppStream.1] AppStream 2.0 fleets should not provide default internet access",
                "Description": "AppStream 2.0 fleet "
                + fleetName
                + " is not configured to provide default internet access.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your fleet should not have default internet access refer to the instructions in the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAppStreamFleet",
                        "Id": fleetArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"fleetName": fleetName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("appstream")
def public_image_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """Check for appstream images marked public

    TODO: Right now, this check is returning all public images including what appear 
    to be globally public images.  My best guess right now is that we could look at 
    the arn of public images that don't have an accountId in the arn and ignore those. 
    """
    # loop through AppStream 2.0 images
    response = appstream.describe_images(Type="PUBLIC", MaxResults=25)
    myAppstreamImages = response["Images"]
    for images in myAppstreamImages:
        imageName = str(images["Name"])
        imageArn = str(images["Arn"])
        # ISO Time
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # create Sec Hub finding
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": imageArn + "/appstream-public-image",
            "ProductArn": "arn:aws:securityhub:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":product/"
            + awsAccountId
            + "/default",
            "GeneratorId": imageArn,
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure",
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[AppStream.2] AppStream 2.0 images you build should not be publicly accessible",
            "Description": "AppStream 2.0 image "
            + imageName
            + " is publicly accessible. Permissions set on images that are shared with you may limit what you can do with those images. Refer to the remediation instructions if this configuration is not intended. Note that AWS managed AppStream 2.0 images will always be publicly accessible",
            "Remediation": {
                "Recommendation": {
                    "Text": "If your image should not be publicly accessible refer to the instructions in the Amazon AppStream 2.0 Administration Guide",
                    "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/administer-images.html#stop-sharing-image-with-all-accounts",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "Other",
                    "Id": imageArn,
                    "Partition": "aws",
                    "Region": awsRegion,
                    "Details": {"Other": {"Image Name": imageName}},
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
                    "ISO 27001:2013 A.13.2.1",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding


@registry.register_check("appstream")
def compromise_appstream_user_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through AppStream 2.0 users
    response = describe_users(cache)
    myAppStreamUsers = response["Users"]
    for users in myAppStreamUsers:
        userArn = str(users["Arn"])
        userName = str(users["UserName"])
        userStatus = str(users["Status"])
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if userStatus == "COMPROMISED":
            # create Sec Hub finding
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": userArn + "/appstream-compromised-user",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Unusual Behaviors/User",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[AppStream.3] AppStream 2.0 users should be monitored for signs of compromise",
                "Description": "AppStream 2.0 user "
                + userName
                + " is compromised. COMPROMISED – The user is disabled because of a potential security threat. Refer to the remediation instructions for information on how to remove them",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To disable and remove compromised users refer to the instructions in the User Pool Administration section of the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/user-pool-admin.html#user-pool-admin-disabling",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": userArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"userName": userName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5" "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": userArn + "/appstream-compromised-user",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Unusual Behaviors/User",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[AppStream.3] AppStream 2.0 users should be monitored for signs of compromise",
                "Description": "AppStream 2.0 user " + userName + " is not compromised.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To disable and remove compromised users refer to the instructions in the User Pool Administration section of the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/user-pool-admin.html#user-pool-admin-disabling",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": userArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"userName": userName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5" "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("appstream")
def userpool_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through AppStream 2.0 users
    response = describe_users(cache)
    myAppStreamUsers = response["Users"]
    for users in myAppStreamUsers:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        userArn = str(users["Arn"])
        userName = str(users["UserName"])
        # find users that do not auth with SAML
        # basic auth & API access will show as non-compliant
        userAuthType = str(users["AuthenticationType"])
        if userAuthType != "SAML":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": userArn + "/appstream-compromised-user",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[AppStream.4] AppStream 2.0 users should be configured to authenticate using SAML",
                "Description": "AppStream 2.0 user "
                + userName
                + " is not configured to authenticate using SAML. This feature offers your users the convenience of one-click access to their AppStream 2.0 applications using their existing identity credentials. You also have the security benefit of identity authentication by your IdP. By using your IdP, you can control which users have access to a particular AppStream 2.0 stack. Refer to the remediation instructions for information on how to remove them",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on setting up SAML refer to the Setting Up SAML section of the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-saml-provider",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": userArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"userName": userName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": userArn + "/appstream-compromised-user",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[AppStream.4] AppStream 2.0 users should be configured to authenticate using SAML",
                "Description": "AppStream 2.0 user "
                + userName
                + " is configured to authenticate using SAML.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on setting up SAML refer to the Setting Up SAML section of the Amazon AppStream 2.0 Administration Guide",
                        "Url": "https://docs.aws.amazon.com/appstream2/latest/developerguide/external-identity-providers-setting-up-saml.html#external-identity-providers-create-saml-provider",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": userArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"userName": userName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
