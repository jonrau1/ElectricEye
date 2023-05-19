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
import base64
import json
import botocore

registry = CheckRegister()

def get_account_alternate_contacts(cache, session):
    response = cache.get("get_account_alternate_contacts")
    if response:
        return response
    
    accountClient = session.client("account")

    accountAlternateContacts = []

    try:
        accountClient.get_alternate_contact(AlternateContactType="BILLING")
        accountAlternateContacts.append("BILLING")
    except botocore.exceptions.ClientError as error:
        print(f"Cannot access Account API because {error}")

    try:
        accountClient.get_alternate_contact(AlternateContactType="OPERATIONS")
        accountAlternateContacts.append("OPERATIONS")
    except botocore.exceptions.ClientError as error:
        print(f"Cannot access Account API because {error}")

    try:
        accountClient.get_alternate_contact(AlternateContactType="SECURITY")
        accountAlternateContacts.append("SECURITY")
    except botocore.exceptions.ClientError as error:
        print(f"Cannot access Account API because {error}")

    cache["get_account_alternate_contacts"] = accountAlternateContacts
    return cache["get_account_alternate_contacts"]

@registry.register_check("account")
def aws_accounts_billing_dedicated_contact_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Account.1] AWS Accounts should have a dedicated contact for Billing identified"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

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

    contacts = get_account_alternate_contacts(cache, session)
    if "BILLING" in contacts:
        billingContactSet = True
    else:
        billingContactSet = False

    if billingContactSet is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-billing-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-billing-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Account.1] AWS Accounts should have a dedicated contact for Billing identified",
            "Description": f"AWS Account {awsAccountId} does not have a dedicated Billing contact identified. You can update alternate contacts for accounts within your organization from the AWS Organizations console, or programmatically with AWS CLI or AWS SDKs. You can use the organization's management account to view and edit account settings for any account in your organization. The primary account holder will continue to receive all email communications to the root account's email. To update alternate contacts with the AWS Organizations console, you need to do some preliminary settings: Your organization must enable all features to manage settings on your member accounts. This allows admin control over the member accounts. You need to enable trusted access for AWS Account Management service. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-billing-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-billing-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Account.1] AWS Accounts should have a dedicated contact for Billing identified",
            "Description": f"AWS Account {awsAccountId} does have a dedicated Billing contact identified.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("account")
def aws_accounts_operations_dedicated_contact_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Account.2] AWS Accounts should have a dedicated contact for Operations identified"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

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

    contacts = get_account_alternate_contacts(cache, session)
    if "OPERATIONS" in contacts:
        opsContactSet = True
    else:
        opsContactSet = False

    if opsContactSet is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-operations-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-operations-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Account.2] AWS Accounts should have a dedicated contact for Operations identified",
            "Description": f"AWS Account {awsAccountId} does not have a dedicated Operations contact identified. You can update alternate contacts for accounts within your organization from the AWS Organizations console, or programmatically with AWS CLI or AWS SDKs. You can use the organization's management account to view and edit account settings for any account in your organization. The primary account holder will continue to receive all email communications to the root account's email. To update alternate contacts with the AWS Organizations console, you need to do some preliminary settings: Your organization must enable all features to manage settings on your member accounts. This allows admin control over the member accounts. You need to enable trusted access for AWS Account Management service. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-operations-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-operations-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Account.2] AWS Accounts should have a dedicated contact for Operations identified",
            "Description": f"AWS Account {awsAccountId} does have a dedicated Operations contact identified.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("account")
def aws_accounts_security_dedicated_contact_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Account.3] AWS Accounts should have a dedicated contact for Security identified"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

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

    contacts = get_account_alternate_contacts(cache, session)
    if "SECURITY" in contacts:
        securityContactSet = True
    else:
        securityContactSet = False

    if securityContactSet is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-security-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-security-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Account.3] AWS Accounts should have a dedicated contact for Security identified",
            "Description": f"AWS Account {awsAccountId} does not have a dedicated Security contact identified. You can update alternate contacts for accounts within your organization from the AWS Organizations console, or programmatically with AWS CLI or AWS SDKs. You can use the organization's management account to view and edit account settings for any account in your organization. The primary account holder will continue to receive all email communications to the root account's email. To update alternate contacts with the AWS Organizations console, you need to do some preliminary settings: Your organization must enable all features to manage settings on your member accounts. This allows admin control over the member accounts. You need to enable trusted access for AWS Account Management service. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/aws-account-security-alternate-contact-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/aws-account-security-alternate-contact-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Account.3] AWS Accounts should have a dedicated contact for Security identified",
            "Description": f"AWS Account {awsAccountId} does have a dedicated Security contact identified.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on setting and updating Alternate Contacts refer to the Accessing or updating the alternate contacts section of the AWS Account Management Reference Guide",
                    "Url": "https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-update-contact-alternate.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": globalRegion,
                "AssetDetails": None,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Account",
                "AssetComponent": "Alternate Contact"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Account_Billing_Alternate_Contact",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END ??