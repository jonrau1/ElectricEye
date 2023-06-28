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
import requests
import os
import datetime
import base64
import json

registry = CheckRegister()

SALESFORCE_FAILED_LOGIN_BREACHING_RATE = os.environ["SALESFORCE_FAILED_LOGIN_BREACHING_RATE"]
SFDC_API_VERSION = os.environ["SFDC_API_VERSION"]

def retrieve_oauth_token(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str):
    """
    Creates a Salesforce OAuth config & returns the access token
    """
    
    response = cache.get("retrieve_oauth_token")
    if response:
        return response

    # Obtain access token using username-password flow
    data = {
        "grant_type": "password",
        "client_id": salesforceAppClientId,
        "client_secret": salesforceAppClientSecret,
        "username": salesforceApiUsername,
        "password": f"{salesforceApiPassword}{salesforceUserSecurityToken}"
    }

    # Retrieve the Token
    token = requests.post(
        "https://login.salesforce.com/services/oauth2/token",
        data=data
    ).json()

    # Parse the Token and the URL of the Instance
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]
    payload = {"access_token": accessToken, "instance_url": instanceUrl}

    cache["retrieve_oauth_token"] = payload
    return cache["retrieve_oauth_token"]

def get_salesforce_users_with_mfa(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str):
    response = cache.get("get_salesforce_users_with_mfa")
    if response:
        return response
    
    token = retrieve_oauth_token(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]

    headers = {
        "Authorization": f"Bearer {accessToken}",
        "Content-Type": "application/json"
    }

    # First call will use a Query to retrieve relevant user data
    url = f"{instanceUrl}/services/data/{SFDC_API_VERSION}/query/"
    query = "SELECT Username, Email, Id, FederationIdentifier, IsActive, LastLoginDate, NumberOfFailedLogins FROM User"
    userQuery = requests.get(url, headers=headers, params={"q": query})
    if userQuery.status_code != 200:
        print("Failed to retrieve users from Salesforce! Exiting.")
        raise userQuery.reason
    # Use a list comprehension to re-sort the data & append MFA data into
    allUsers = [user for user in userQuery.json()["records"]]
    del userQuery
    # Loop the new "allUsers" list and use a WHERE clause to get the per-user MFA data - this will not work unless the Salesforce User has
    # MFA permissions within their Scope
    for userData in allUsers:
        # Parse User ID for a WHERE clause
        userId = userData["Id"]
        mfaQuery = f"""
        SELECT Id, ExternalId, HasBuiltInAuthenticator, HasSalesforceAuthenticator, HasSecurityKey, HasTotp, HasUserVerifiedEmailAddress, HasUserVerifiedMobileNumber FROM TwoFactorMethodsInfo WHERE UserId = '{userId}'
        """
        mfaQueryReq = requests.get(url, headers=headers, params={"q": mfaQuery})
        if mfaQueryReq.status_code == 200:
            userData["TwoFactorMethodsInfo"] = mfaQueryReq.json()["records"]
        else:
            userData["TwoFactorMethodsInfo"] = []

    # Return a tuple of the list of MFA-enriched users, and the Instance URL which is the GUID for the instance
    payload = (allUsers, instanceUrl)

    cache["get_salesforce_users_with_mfa"] = payload
    return cache["get_salesforce_users_with_mfa"]

@registry.register_check("salesforce.users")
def salesforce_active_user_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.Users.1] Salesforce users that are not active should have their activity reviewed and records transferred
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_users_with_mfa(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    for user in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Basic data for the users
        username = user["Username"]
        userId = user["Id"]
        # this is a failing check
        if user["IsActive"] is not True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Salesforce.Users.1] Salesforce users that are not active should have their activity reviewed and records transferred",
                "Description": f"Salesforce user {username} from instance {payload[1]} is not an active user and should their activity reviewed and records transferred. Salesforce lets you deactivate users, but not delete them outright. A user can own accounts, leads, and groups, and can be on multiple teams. Removing a user from Salesforce affects many processes in the org. After departure from the org, you obviously don't want the user to retain access to their account. However, merely deleting a user can result in orphaned records and the loss of critical business information. For these reasons, deactivating rather than deleting the user is the appropriate action to take. Deactivation removes the user's login access, but it preserves all historical activity and records, making it easy to transfer ownership to other users. For situations where changing ownership to other uses must be done before deactivation, freezing the user prevents login to the org and access to the user's accounts. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on deactivated and removing users and their records refer to the Delete Users section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.deactivating_users.htm&type=5"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Salesforce",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": payload[1],
                    "AssetRegion": salesforceInstanceLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SalesforceUser",
                        "Id": f"{payload[1]}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "Username": username,
                                "Id": userId
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
                "Id": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.Users.1] Salesforce users that are not active should have their activity reviewed and records transferred",
                "Description": f"Salesforce user {username} from instance {payload[1]} is an active user.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on deactivated and removing users and their records refer to the Delete Users section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.deactivating_users.htm&type=5"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Salesforce",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": payload[1],
                    "AssetRegion": salesforceInstanceLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SalesforceUser",
                        "Id": f"{payload[1]}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "Username": username,
                                "Id": userId
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

@registry.register_check("salesforce.users")
def salesforce_active_user_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.Users.2] Salesforce users that are active should have multi-factor authentication (MFA) enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_users_with_mfa(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    for user in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(user,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Basic data for the users
        username = user["Username"]
        userId = user["Id"]
        # Logic is to check if theyre Active, check if they do have any MFA data, and if so check if any are active
        if user["IsActive"] is True:
            if user["TwoFactorMethodsInfo"]:
                userMfa = user["TwoFactorMethodsInfo"][0]
                # use "any" method to check if any of the possible MFA sources are active
                if any(
                    userMfa["HasBuiltInAuthenticator"],
                    userMfa["HasSalesforceAuthenticator"],
                    userMfa["HasSecurityKey"],
                    userMfa["HasTotp"]
                ):
                    userHasMfa = True
        # this is a failing check
        if userHasMfa is not True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Salesforce.Users.2] Salesforce users that are active should have multi-factor authentication (MFA) enabled",
                "Description": f"Salesforce user {username} from instance {payload[1]} does not have multi-factor authentication (MFA) enabled or is not an active user. MFA is an effective way to increase protection for user accounts against common threats like phishing attacks, credential stuffing, and account takeovers. It adds another layer of security to your login process by requiring users to enter two or more pieces of evidence — or factors — to prove they are who they say they are. One factor is something the user knows, such as their username and password combination. Other factors are verification methods that the user has in their possession, such as an authenticator app or security key. A familiar example of MFA at work is the two factors needed to withdraw money from an ATM. Your ATM card is something that you have and your PIN is something you know. To ensure that MFA is required for all your Salesforce users, you can turn it on directly in your Salesforce products or use your SSO provider's MFA service. Salesforce products include MFA functionality at no extra cost. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up MFA for Users refer to the Salesforce Multi-Factor Authentication FAQ section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=000388806&type=1"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Salesforce",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": payload[1],
                    "AssetRegion": salesforceInstanceLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SalesforceUser",
                        "Id": f"{payload[1]}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "Username": username,
                                "Id": userId
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
                "Id": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{payload[1]}/user/{userId}/salesforce-active-user-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.Users.2] Salesforce users that are active should have multi-factor authentication (MFA) enabled",
                "Description": f"Salesforce user {username} from instance {payload[1]} does have multi-factor authentication (MFA) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up MFA for Users refer to the Salesforce Multi-Factor Authentication FAQ section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=000388806&type=1"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Salesforce",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": payload[1],
                    "AssetRegion": salesforceInstanceLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Users",
                    "AssetComponent": "User"
                },
                "Resources": [
                    {
                        "Type": "SalesforceUser",
                        "Id": f"{payload[1]}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "Username": username,
                                "Id": userId
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

# End ??