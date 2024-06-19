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

import requests
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

API_ROOT = "https://graph.microsoft.com/v1.0"

def get_oauth_token(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_oauth_token")
    if response:
        return response

    # Retrieve an OAuth Token for the Microsoft Graph APIs
    tokenUrl = f"https://login.microsoftonline.com/{tenantId}/oauth2/token"
    resourceAppIdUri = "https://graph.microsoft.com"

    tokenData = {
        "client_id": clientId,
        "grant_type": "client_credentials",
        "resource" : resourceAppIdUri,
        "client_secret": clientSecret
    }

    r = requests.post(tokenUrl, data=tokenData)

    if r.status_code != 200:
        raise r.reason
    else:
        token = r.json()["access_token"]

        cache["get_oauth_token"] = token
        return cache["get_oauth_token"]
    
def get_conditional_access_policies(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_conditional_access_policies")
    if response:
        return response

    # Retrieve the Token from Cache
    headers = {
        "Authorization": f"Bearer {get_oauth_token(cache, tenantId, clientId, clientSecret)}"
    }

    r = requests.get(
        f"{API_ROOT}/identity/conditionalAccess/policies",
        headers=headers
    )

    if r.status_code != 200:
        raise r.reason
    else:
        cache["get_conditional_access_policies"] = r.json()["value"]
        return cache["get_conditional_access_policies"]
    
@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_legacy_authentication_methods_block_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.1] Microsoft 365 Conditional Access policies should be configured to block legacy authentication methods
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the Legacy Authentication Block (Exchange ActiveSync) Conditional Access Policy with a List Comprehension
    # First, check if "exchangeActiveSync" and "other" is in the Client App Types - this is what SecureScore wants
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Finally, ensure that the Action (["grantControls"]["builtInControls"]) is set to Block - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    legacyAuthCaPolicy = [
        policy for policy in policies
        if ("exchangeActiveSync" and "other") in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["grantControls"] is not None
        and "block" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if legacyAuthCaPolicy:
        assetJson = json.dumps(legacyAuthCaPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = legacyAuthCaPolicy[0]["displayName"]
        id = legacyAuthCaPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-legacy-authn-methods-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-legacy-authn-methods-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.1] Microsoft 365 Conditional Access policies should be configured to block legacy authentication methods",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block legacy authentication methods.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Conditional Access Policy to block legacy authentication refer to the Block legacy authentication with Azure AD with Conditional Access section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockLegacyAuthentication_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-legacy-authn-methods-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-legacy-authn-methods-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.1] Microsoft 365 Conditional Access policies should be configured to block legacy authentication methods",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to block legacy authentication methods. To give your users easy access to your cloud apps, Azure Active Directory (Azure AD) supports a broad variety of authentication protocols including legacy authentication. However, legacy authentication doesn't support things like multifactor authentication (MFA). MFA is a common requirement to improve security posture in organizations. If you are ready to block legacy authentication to improve your tenant's protection, you can accomplish this goal with Conditional Access. While rolling out legacy authentication blocking protection, Microsoft recommends a phased approach, rather than disabling it for all users all at once. Customers may choose to first begin disabling basic authentication on a per-protocol basis, by applying Exchange Online authentication policies, then (optionally) also blocking legacy authentication via Conditional Access policies when ready. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Conditional Access Policy to block legacy authentication refer to the Block legacy authentication with Azure AD with Conditional Access section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_mfa_medium_risk_signin_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.2] Microsoft 365 Conditional Access policies should be configured to enforce MFA on Medium Risk sign-ins
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the MFA enforcement for Risky sign-ins Conditional Access Policy with a List Comprehension
    # First, check if sign-in Risk Levels have Medium OR High - either is fine for what SecureScore wants
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that all Client App Types are in scope
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Finally, ensure that the Action (["grantControls"]["builtInControls"]) is set to enforce MFA - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    mfaForRiskySigninPolicy = [
        policy for policy in policies
        if ("high" or "medium") in policy["conditions"]["signInRiskLevels"]
        and policy["state"] == "enabled"
        and "all" in policy["conditions"]["clientAppTypes"]
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["grantControls"] is not None
        and "mfa" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if mfaForRiskySigninPolicy:
        assetJson = json.dumps(mfaForRiskySigninPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = mfaForRiskySigninPolicy[0]["displayName"]
        id = mfaForRiskySigninPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-mfa-medium-risk-sigin-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-mfa-medium-risk-sigin-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.2] Microsoft 365 Conditional Access policies should be configured to enforce MFA on Medium Risk sign-ins",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to enforce MFA on Medium Risk sign-ins.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Conditional Access Policy to challenge for MFA on risky sign-ins refer to the Common Conditional Access policy: Sign-in risk-based multifactor authentication section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/mfaMediumRiskSignIn_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-mfa-medium-risk-sigin-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-mfa-medium-risk-sigin-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.2] Microsoft 365 Conditional Access policies should be configured to enforce MFA on Medium Risk sign-ins",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to enforce MFA on Medium Risk sign-ins. Most users have a normal behavior that can be tracked, when they fall outside of this norm it could be risky to allow them to just sign in. You may want to block that user or maybe just ask them to perform multifactor authentication to prove that they're really who they say they are. A sign-in risk represents the probability that a given authentication request isn't authorized by the identity owner. Organizations with Azure AD Premium P2 licenses can create Conditional Access policies incorporating Azure AD Identity Protection sign-in risk detections. There are two locations where this policy may be configured, Conditional Access and Identity Protection. Configuration using a Conditional Access policy is the preferred method providing more context including enhanced diagnostic data, report-only mode integration, Graph API support, and the ability to utilize other Conditional Access attributes like sign-in frequency in the policy. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Conditional Access Policy to challenge for MFA on risky sign-ins refer to the Common Conditional Access policy: Sign-in risk-based multifactor authentication section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_location_based_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.3] Microsoft 365 Conditional Access policies should be configured to enforce Location-based Conditional Access (LBCA) by blocking unsanctioned countries
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the Location-based Conditional Access Policy with a List Comprehension - we don't care what the Locations are, really
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, *most important part*, check that Locations are actually specified and use "is not None" to ignore non-LBCAs
    # Finally, ensure that the Action (["grantControls"]["builtInControls"]) is set to Block - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    lbcaPolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["conditions"]["locations"] is not None
        and policy["conditions"]["locations"]["includeLocations"]
        and policy["grantControls"] is not None
        and "block" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if lbcaPolicy:
        assetJson = json.dumps(lbcaPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = lbcaPolicy[0]["displayName"]
        id = lbcaPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-lbca-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-lbca-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.3] Microsoft 365 Conditional Access policies should be configured to enforce Location-based Conditional Access (LBCA) by blocking unsanctioned countries",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to enforce Location-based Conditional Access (LBCA) by blocking unsanctioned countries.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Location-based Conditional Access (LBCA) refer to the Conditional Access: Block access by location section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-location"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/locationBasedConditionalAccess_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-lbca-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-lbca-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.3] Microsoft 365 Conditional Access policies should be configured to enforce Location-based Conditional Access (LBCA) by blocking unsanctioned countries",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to enforce Location-based Conditional Access (LBCA) by blocking unsanctioned countries. With the location condition in Conditional Access, you can control access to your cloud apps based on the network location of a user. The location condition is commonly used to block access from countries/regions where your organization knows traffic shouldn't come from. Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access. You must first configure a Named Location containing countries by IP-geolocation, roll this policy out in stages as you can potentially cause outages when Managed Identities or Service Principals attempt actions from IP ranges of cloud or VPN providers in your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a Location-based Conditional Access (LBCA) refer to the Conditional Access: Block access by location section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-location"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_block_device_unused_os_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.4] Microsoft 365 Conditional Access policies should be configured to block devices using unsupported operating systems
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the Unused Device OS blocking Conditional Access Policy with a List Comprehension - we don't care about what is excluded
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, *most important part*, check that Platforms are actually specified and use "is not None" to ignore non-LBCAs
    # Finally, ensure that the Action (["grantControls"]["builtInControls"]) is set to Block - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    unusedDeviceOsBlockPolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["conditions"]["platforms"] is not None
        and policy["conditions"]["platforms"]["includePlatforms"]
        and policy["grantControls"] is not None
        and "block" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if unusedDeviceOsBlockPolicy:
        assetJson = json.dumps(unusedDeviceOsBlockPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = unusedDeviceOsBlockPolicy[0]["displayName"]
        id = unusedDeviceOsBlockPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-unused-os-device-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-unused-os-device-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.4] Microsoft 365 Conditional Access policies should be configured to block devices using unsupported operating systems",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block devices using unsupported operating systems.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking unknown or unsupported devices based on operating system refer to the Common Conditional Access policy: Block access for unknown or unsupported device platform section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-policy-unknown-unsupported-device"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockUnusedDeviceOs_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-unused-os-device-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-unused-os-device-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.4] Microsoft 365 Conditional Access policies should be configured to block devices using unsupported operating systems",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to block devices using unsupported operating systems. This policy will block users from accessing company resources if their Device has an unknown or unsupported Operating System, however consider exempting Service accounts and service principals, such as the Azure AD Connect Sync Account. Service accounts are non-interactive accounts that aren't tied to any particular user. They're normally used by back-end services allowing programmatic access to applications, but are also used to sign in to systems for administrative purposes. Service accounts like these should be excluded since MFA can't be completed programmatically. Calls made by service principals won't be blocked by Conditional Access policies scoped to users. Use Conditional Access for workload identities to define policies targeting service principals. This Policy should mirror any Device Compliance policies and should be configured with support of central IT functions as they will likely have access to asset inventories and understand what permitting Operating Systems are in use. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking unknown or unsupported devices based on operating system refer to the Common Conditional Access policy: Block access for unknown or unsupported device platform section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-policy-unknown-unsupported-device"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_block_device_compliance_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.5] Microsoft 365 Conditional Access policies should be configured to block non-compliant devices from accessing company resources
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the Require Compliant Devices Conditional Access Policy with a List Comprehension - we don't care about what is excluded (probably everything except Windows)
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, check that Platforms are actually specified and use "is not None" to ignore non-LBCAs
    # Finally, *most important part*, ensure that the Action (["grantControls"]["builtInControls"]) is set to compliantDevice - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    requireCompliantDevicePolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["conditions"]["platforms"] is not None
        and policy["conditions"]["platforms"]["includePlatforms"]
        and policy["grantControls"] is not None
        and "compliantDevice" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if requireCompliantDevicePolicy:
        assetJson = json.dumps(requireCompliantDevicePolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = requireCompliantDevicePolicy[0]["displayName"]
        id = requireCompliantDevicePolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-noncompliant-device-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-noncompliant-device-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.5] Microsoft 365 Conditional Access policies should be configured to block non-compliant devices from accessing company resources",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block non-compliant devices from accessing company resources.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking non-compliant devices refer to the Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockNoncompliantDevice_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-noncompliant-device-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-noncompliant-device-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.5] Microsoft 365 Conditional Access policies should be configured to block non-compliant devices from accessing company resources",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to block non-compliant devices from accessing company resources. Organizations who have deployed Microsoft Intune can use the information returned from their devices to identify devices that meet compliance requirements such as requiring a PIN (and/or PIN complexity), full disk encryption, specific OS version, a non-rooted/jailbroken device and much more. Policy compliance information is sent to Azure AD where Conditional Access decides to grant or block access to resources. Consider exempting Service accounts and service principals, such as the Azure AD Connect Sync Account. Service accounts are non-interactive accounts that aren't tied to any particular user. They're normally used by back-end services allowing programmatic access to applications, but are also used to sign in to systems for administrative purposes. Service accounts like these should be excluded since MFA can't be completed programmatically. Calls made by service principals won't be blocked by Conditional Access policies scoped to users. Use Conditional Access for workload identities to define policies targeting service principals. Also consider a grace period of reporting-only to give time for users to install and/or configure software and settings. Blocking non-compliant devices can help minimize your exposure to adversaries accessing your resources, when used alongside Defender for Endpoint and Intune, Conditional Access can dramatically reduce the ability for misconfigured and exploitable devices entering your zone of trust. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking non-compliant devices refer to the Common Conditional Access policy: Require a compliant device, hybrid Azure AD joined device, or multifactor authentication for all users section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-compliant-device"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_block_device_app_protection_policy_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.6] Microsoft 365 Conditional Access policies should be configured to require devices have an associated Application Protection Policy before accessing company resources
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find any Application Protection Policy Conditional Access Policy with a List Comprehension - we don't care about what it's for and which devices
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes any Application within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, check that Platforms are actually specified and use "is not None" to ignore non-LBCAs
    # Finally, *most important part*, ensure that the Action (["grantControls"]["builtInControls"]) is set to compliantApplication - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    appProtectionPolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["conditions"]["platforms"] is not None
        and policy["conditions"]["platforms"]["includePlatforms"]
        and policy["grantControls"] is not None
        and "compliantApplication" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if appProtectionPolicy:
        assetJson = json.dumps(appProtectionPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = appProtectionPolicy[0]["displayName"]
        id = appProtectionPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-device-without-app-protection-policies-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-device-without-app-protection-policies-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.6] Microsoft 365 Conditional Access policies should be configured to require devices have an associated Application Protection Policy before accessing company resources",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to require devices have an associated Application Protection Policy before accessing company resources.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking devices without an Application Protection Policy refer to the Common Conditional Access policy: Require approved client apps or app protection policy section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-policy-approved-app-or-app-protection"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/devicesRequireApplicationProtectionPolicy_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-device-without-app-protection-policies-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-device-without-app-protection-policies-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.6] Microsoft 365 Conditional Access policies should be configured to require devices have an associated Application Protection Policy before accessing company resources",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to require devices have an associated Application Protection Policy before accessing company resources. People regularly use their mobile devices for both personal and work tasks. While making sure staff can be productive, organizations also want to prevent data loss from applications on devices they may not manage fully. With Conditional Access, organizations can restrict access to approved (modern authentication capable) client apps with Intune app protection policies. For older client apps that may not support app protection policies, administrators can restrict access to approved client apps. App protection policies are supported on iOS and Android only and not all applications that are supported as approved applications or support application protection policies. For users with mobile devices (either personal, BYOD or company-issued) an Application Protection Policy can ensure they meet minimum required security configurations and in the event a device is lost, it can be permanently blocked or remotely wiped, limiting the potential for adversaries to leverage the devices for illicit activity. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy for blocking devices without an Application Protection Policy refer to the Common Conditional Access policy: Require approved client apps or app protection policy section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-policy-approved-app-or-app-protection"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_block_high_risk_users_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.7] Microsoft 365 Conditional Access policies should be configured to block High Risk Users
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find Conditional Access Policies which Block sign-in of High Risk Users
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, ensure that High User Risk levels are specified in the User Risk Levels
    # Finally, *most important part*, ensure that the Action (["grantControls"]["builtInControls"]) is set to compliantApplication - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    highRiskUserBlockPolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and "high" in policy["conditions"]["userRiskLevels"]
        and "block" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if highRiskUserBlockPolicy:
        assetJson = json.dumps(highRiskUserBlockPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = highRiskUserBlockPolicy[0]["displayName"]
        id = highRiskUserBlockPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-high-risk-users-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-high-risk-users-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.7] Microsoft 365 Conditional Access policies should be configured to block High Risk Users",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block High Risk Users.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy based on High Risk Users refer to the Common Conditional Access policy: User risk-based password change section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk-user"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockHighRiskUsers_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-high-risk-users-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-high-risk-users-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.7] Microsoft 365 Conditional Access policies should be configured to block High Risk Users",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are not configured to block High Risk Users. The Microsoft 365 User risk level is a feature that helps to determine the risk of a user account in Microsoft 365. It uses Azure AD Identity Protection, which analyses multiple signals including IP address, device state, and suspicious activity, to determine the risk level of a user account. While the full algorithm is not known High risk denotes user accounts that are considered to be compromised and should be blocked. By using the Microsoft 365 User risk level feature, organizations can detect and respond to suspicious account activity more effectively, helping to prevent unauthorized access to sensitive information and systems. This is an important security feature that can help to reduce the risk of data breaches and comply with regulatory requirements. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy based on High Risk Users refer to the Common Conditional Access policy: User risk-based password change section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk-user"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_block_high_risk_signin_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.ConditionalAccess.8] Microsoft 365 Conditional Access policies should be configured to block High Risk Sign-ins
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find Conditional Access Policies which Block sign-in of High Risk sign-ins
    # First, check if all Client App Types are in scope
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Then, ensure that High User Risk levels are specified in the User Risk Levels
    # Finally, *most important part*, ensure that the Action (["grantControls"]["builtInControls"]) is set to compliantApplication - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    highRiskUserSigninBlockPolicy = [
        policy for policy in policies
        if "all" in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and "high" in policy["conditions"]["signInRiskLevels"]
        and "block" in policy["grantControls"]["builtInControls"]
    ]
    # Passing checks will be first!
    if highRiskUserSigninBlockPolicy:
        assetJson = json.dumps(highRiskUserSigninBlockPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = highRiskUserSigninBlockPolicy[0]["displayName"]
        id = highRiskUserSigninBlockPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-high-risk-signins-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-high-risk-signins-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.8] Microsoft 365 Conditional Access policies should be configured to block High Risk Sign-ins",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block High Risk Sign-ins.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy based on High Risk Sign-ins refer to the Common Conditional Access policy: Sign-in risk-based multifactor authentication section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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
    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockHighRiskSignIns_placeholder"
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-conditional-access-polices-block-high-risk-signins-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-conditional-access-polices-block-high-risk-signins-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.ConditionalAccess.8] Microsoft 365 Conditional Access policies should be configured to block High Risk Sign-ins",
            "Description": f"Microsoft 365 Conditional Access policies for M365 Tenant {tenantId} are configured to block High Risk Sign-ins. While the full algorithm is not known, sign-in attempts that are determined to be high risk are considered to be malicious and should be blocked. By using the Microsoft 365 User risk level feature, organizations can detect and respond to suspicious account activity more effectively, helping to prevent unauthorized access to sensitive information and systems. This is an important security feature that can help to reduce the risk of data breaches and comply with regulatory requirements. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up a policy based on High Risk Sign-ins refer to the Common Conditional Access policy: Sign-in risk-based multifactor authentication section of the Microsoft 365 Conditional Access documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-risk"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Identity & Access Management",
                "AssetService": "Microsoft 365 Conditional Access",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "M365ConditionalAccessPolicy",
                    "Id": resourceId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "Id": id,
                            "DisplayName": displayName
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-4",
                    "NIST CSF V1.1 PR.PT-3",
                    "NIST CSF V1.1 DE.CM-7",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-5",
                    "NIST SP 800-53 Rev. 4 AC-6",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AU-12",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CM-3",
                    "NIST SP 800-53 Rev. 4 CM-7",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PE-3",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 PE-20",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.3",
                    "AICPA TSC CC7.2",
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

## END ??