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

@registry.register_check("appstream")
def default_internet_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppStream.1] AppStream 2.0 fleets should not provide default internet access"""
    appstream = session.client("appstream")
    # loop through AppStream 2.0 fleets
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        myAppstreamFleets = appstream.describe_fleets()["Fleets"]
        for fleet in myAppstreamFleets:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(fleet,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            fleetArn = str(fleet["Arn"])
            fleetName = str(fleet["DisplayName"])
            # find fleets that are configured to provide default internet access
            defaultInternetAccessCheck = str(fleet["EnableDefaultInternetAccess"])
            if defaultInternetAccessCheck == "True":
                # this is a failing check
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "End User Computing",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "Fleet"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamFleet",
                            "Id": fleetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"fleetName": fleetName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "End User Computing",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "Fleet"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamFleet",
                            "Id": fleetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"fleetName": fleetName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
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
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            pass
        else:
            print(f'We found another error! {error}')

@registry.register_check("appstream")
def public_image_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppStream.2] AppStream 2.0 images you build should not be publicly accessible"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    appstream = session.client("appstream")
    try:
        myAppstreamImages = appstream.describe_images()["Images"]
        for images in myAppstreamImages:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(images,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            imageName = str(images["Name"])
            imageArn = str(images["Arn"])        
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": imageArn + "/appstream-public-image",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "End User Computing",
                    "AssetService": "AWS AppStream 2.0",
                    "AssetComponent": "Image"
                },
                "Resources": [
                    {
                        "Type": "AwsAppStreamImage",
                        "Id": imageArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"Image Name": imageName}},
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
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            pass
        else:
            print(f'We found another error! {error}')

@registry.register_check("appstream")
def compromise_appstream_user_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppStream.3] AppStream 2.0 users should be monitored for signs of compromise"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    appstream = session.client("appstream")
    try:
        # loop through AppStream 2.0 users
        myAppStreamUsers = appstream.describe_users(AuthenticationType="USERPOOL")["Users"]
        for users in myAppStreamUsers:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(users,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            userArn = str(users["Arn"])
            userName = str(users["UserName"])
            userStatus = str(users["Status"])
            if userStatus == "COMPROMISED":
                # this is a failing check
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"UserName": userName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-3",
                            "NIST CSF V1.1 DE.CM-7",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 CM-3",
                            "NIST SP 800-53 Rev. 4 CM-8",
                            "NIST SP 800-53 Rev. 4 PE-3",
                            "NIST SP 800-53 Rev. 4 PE-6",
                            "NIST SP 800-53 Rev. 4 PE-20",
                            "NIST SP 800-53 Rev. 4 PM-12",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 RA-3",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AICPA TSC CC3.2",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 Clause 6.1.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.14.2.7",
                            "ISO 27001:2013 A.15.2.1"
                        ]
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"UserName": userName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-3",
                            "NIST CSF V1.1 DE.CM-7",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 CM-3",
                            "NIST SP 800-53 Rev. 4 CM-8",
                            "NIST SP 800-53 Rev. 4 PE-3",
                            "NIST SP 800-53 Rev. 4 PE-6",
                            "NIST SP 800-53 Rev. 4 PE-20",
                            "NIST SP 800-53 Rev. 4 PM-12",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 RA-3",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AICPA TSC CC3.2",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 Clause 6.1.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.14.2.7",
                            "ISO 27001:2013 A.15.2.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            pass
        else:
            print(f'We found another error! {error}')

@registry.register_check("appstream")
def userpool_auth_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppStream.4] AppStream 2.0 users should be configured to authenticate using SAML"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    appstream = session.client("appstream")
    try:
        # loop through AppStream 2.0 users
        myAppStreamUsers = appstream.describe_users(AuthenticationType="USERPOOL")["Users"]
        for users in myAppStreamUsers:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(users,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            userArn = str(users["Arn"])
            userName = str(users["UserName"])
            # find users that do not auth with SAML basic auth & API access will show as non-compliant
            userAuthType = str(users["AuthenticationType"])
            if userAuthType != "SAML":
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": userArn + "/appstream-userpool-auth-check",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"UserName": userName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-6",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 IA-1",
                            "NIST SP 800-53 Rev. 4 IA-2",
                            "NIST SP 800-53 Rev. 4 IA-4",
                            "NIST SP 800-53 Rev. 4 IA-5",
                            "NIST SP 800-53 Rev. 4 IA-8",
                            "NIST SP 800-53 Rev. 4 PE-2",
                            "NIST SP 800-53 Rev. 4 PS-3",
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
                    "Id": userArn + "/appstream-userpool-auth-check",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS AppStream 2.0",
                        "AssetComponent": "User"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppStreamUser",
                            "Id": userArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"UserName": userName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-6",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 IA-1",
                            "NIST SP 800-53 Rev. 4 IA-2",
                            "NIST SP 800-53 Rev. 4 IA-4",
                            "NIST SP 800-53 Rev. 4 IA-5",
                            "NIST SP 800-53 Rev. 4 IA-8",
                            "NIST SP 800-53 Rev. 4 PE-2",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            pass
        else:
            print(f'We found another error! {error}')