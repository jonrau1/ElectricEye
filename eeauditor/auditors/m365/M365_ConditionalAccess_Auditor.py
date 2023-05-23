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
def m365_conditional_access_legacy_authentication_methods_block_policy_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
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

## END ??