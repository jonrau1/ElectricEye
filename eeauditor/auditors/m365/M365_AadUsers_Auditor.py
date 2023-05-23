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

def get_aad_users_with_enrichment(cache, tenantId, clientId, clientSecret):

    response = cache.get("get_aad_users_with_enrichment")
    if response:
        return response

    # Retrieve the Token from Cache
    token = get_oauth_token(cache, tenantId, clientId, clientSecret)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    userList = []
    listUsersUrl = "https://graph.microsoft.com/v1.0/users"

    # Implement pagination here in case a shitload of Users are returned
    try:
        listusers = json.loads(requests.get(listUsersUrl,headers=headers).text)
        for user in listusers["value"]:
            userList.append(user)

        while listusers["@odata.nextLink"]:
            listusers = json.loads(requests.get(listusers["@odata.nextLink"], headers=headers).text)
            if "@odata.nextLink" in listusers:
                listUsersUrl = listusers["@odata.nextLink"]
            else:
                for user in listusers["value"]:
                    userList.append(user)
                break

            for user in listusers["value"]:
                userList.append(user)
    except KeyError:
        print("No more pagination for AD Users.")

    print(f"{len(userList)} AD Users found. Attempting to retrieve MFA device & Identity Protection information.")

    userList = check_user_mfa_and_risk(userList)
    
    # Print the len() again just in case there was an issue, not like there is anything to do about it though
    print(f"Done retrieving MFA details for {len(userList)} users!")

    cache["get_aad_users_with_enrichment"] = userList
    return cache["get_aad_users_with_enrichment"]

def check_user_mfa_and_risk(token, users):
    """
    This function receives a full list of Users adds a list of authentication methods, and
    adds Identity Protection Risky User & Sign-in (Detection) information and returns the list
    """

    headers = {
        "Authorization": f"Bearer {token}"
    }

    riskDetections = get_identity_protection_risk_detections(token)
    riskyUsers = get_identity_protection_risky_users(token)

    enrichedUsers = []

    for user in users:
        userId = user["id"]

        # Use a list comprehension to check if the User has any Risk Detections - but only if there is a list to comprehend ;)
        if riskDetections:
            userRiskDetections = [risk for risk in riskDetections if risk["id"] == userId]
            if userRiskDetections:
                user["identityProtectionRiskDetections"] = userRiskDetections
            else:
                user["identityProtectionRiskDetections"] = []
        else:
            user["identityProtectionRiskDetections"] = []

        # Use a list comprehension to check if the User is...Risky :O - but only if there is a list to comprehend ;)
        # Use a dictionary here as there *should* only ever be one entry per user
        if riskyUsers:
            userBeingRiskyAndShit = [riskuser for riskuser in riskyUsers if riskuser["id"] == userId]
            if userBeingRiskyAndShit:
                user["identityProtectionRiskyUser"] = userBeingRiskyAndShit[0]
            else:
                user["identityProtectionRiskyUser"] = {}
        else:
            user["identityProtectionRiskyUser"] = {}

        # Get the MFA Devices now
        r = requests.get(
            f"{API_ROOT}/users/{userId}/authentication/methods",
            headers=headers
        )

        if r.status_code != 200:
            print(f"Unable to get MFA for User {id} because {r.reason}")
            user["authenticationMethods"] = []
        else:
            user["authenticationMethods"] = json.loads(r.text)["value"]
            enrichedUsers.append(user)
    
    return enrichedUsers

def get_identity_protection_risk_detections(token):
    """
    Returns a list of Risk Detections from Identity Protection, these are the "Risky Sign-ins"
    """

    headers = {
        "Authorization": f"Bearer {token}"
    }

    r = requests.get(
        f"{API_ROOT}/identityProtection/riskDetections",
        headers=headers
    )

    if r.status_code != 200:
        print(f"Unable to get riskDetections because {r.reason}")
        return []
    else:
        return json.loads(r.text)["value"]

def get_identity_protection_risky_users(token):
    """
    Returns a list of Risky Users from Identity Protection
    """

    headers = {
        "Authorization": f"Bearer {token}"
    }

    r = requests.get(
        f"{API_ROOT}/identityProtection/riskyUsers",
        headers=headers
    )

    if r.status_code != 200:
        print(f"Unable to get riskyUsers because {r.reason}")
        return []
    else:
        return json.loads(r.text)["value"]
    
@registry.register_check("m365.mde")
def m365_aad_user_mfa_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.AadUser.1] Azure Active Directory users should have at least one Multi-factor Authentication (MFA) device registered
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for user in get_aad_users_with_enrichment(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        userId = user["id"]
        displayName = user["displayName"]
        userPrincipalName = user["userPrincipalName"]

        # By default Password is an authentication method, which is...stupid, but okay. If there is only 1 item (or somehow none)
        # then that is a failing finding and really bad
        if len(user["authenticationMethods"]) <= 1:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/{userId}/azure-ad-user-mfa-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/{userId}/azure-ad-user-mfa-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[M365.AadUser.1] Azure Active Directory users should have at least one Multi-factor Authentication (MFA) device registered",
                "Description": f"Azure Active Directory user {userPrincipalName} in M365 Tenant {tenantId} does not have at least one Multi-factor Authentication (MFA) device registered. Passwords are the most common method of authenticating a sign-in to a computer or online service, but they're also the most vulnerable. People can choose easy passwords and use the same passwords for multiple sign-ins to different computers and services. To provide an extra level of security for sign-ins, you must use multifactor authentication (MFA), which uses both a password, which should be strong, and an additional verification method based on either something you have with you that isn't easily duplicated, such as a smart phone or something you uniquely and biologically have, such as your fingerprints, face, or other biometric attribute. The additional verification method isn't employed until after the user's password has been verified. With MFA, even if a strong user password is compromised, the attacker doesn't have your smart phone or your fingerprint to complete the sign-in. Ensure you understand the context behind the user, some Users may be setup just for their email and may not require MFA. That said, consider using Service Principals or Email Aliases for those purposes instead of creating an entirely new user as it can also consume license capacity and lead to higher costs and more failing findings (like this one!). Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up multi-factor authentication refer to the Multifactor authentication for Microsoft 365 section of the Microsoft 365 admin center documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/multi-factor-authentication-microsoft-365?view=o365-worldwide"
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
                    "AssetService": "Azure Active Directory",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "AzureActiveDirectoryUser",
                        "Id": f"{tenantId}/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": userId,
                                "DisplayName": displayName,
                                "UserPrincipalName": userPrincipalName
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/{userId}/azure-ad-user-mfa-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/{userId}/azure-ad-user-mfa-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.AadUser.1] Azure Active Directory users should have at least one Multi-factor Authentication (MFA) device registered",
                "Description": f"Azure Active Directory user {userPrincipalName} in M365 Tenant {tenantId} does have at least one Multi-factor Authentication (MFA) device registered. MFA factors should still be reviewed to ensure they are in compliance with your Policies and are functioning.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up multi-factor authentication refer to the Multifactor authentication for Microsoft 365 section of the Microsoft 365 admin center documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/multi-factor-authentication-microsoft-365?view=o365-worldwide"
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
                    "AssetService": "Azure Active Directory",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "AzureActiveDirectoryUser",
                        "Id": f"{tenantId}/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": userId,
                                "DisplayName": displayName,
                                "UserPrincipalName": userPrincipalName
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

## END ??