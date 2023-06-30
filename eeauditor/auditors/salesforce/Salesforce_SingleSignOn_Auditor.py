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

def get_salesforce_saml_sso_config(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str):
    response = cache.get("get_salesforce_saml_sso_config")
    if response:
        return response
    
    token = retrieve_oauth_token(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]

    headers = {
        "Authorization": f"Bearer {accessToken}",
        "Content-Type": "application/json"
    }

    # Query out all possible values for SamlSsoConfig
    url = f"{instanceUrl}/services/data/{SFDC_API_VERSION}/query/"
    query = """
    SELECT AttributeFormat, AttributeName, Audience, DeveloperName, ErrorUrl, ExecutionUserID, IdentityLocation, IdentityMapping, Issuer, Language, LoginUrl, LogoutUrl, MasterLabel, NamespacePrefix, OptionsSpInitBinding, OptionsUseConfigRequestMethod, OptionsUseSameDigestAlgoForSigning, OptionsRequireMfaSaml, OptionsUserProvisioning, RequestSignatureMethod, SamlJitHandlerId, SingleLogoutBinding, SingleLogoutUrl, ValidationCert, Version 
    FROM SamlSsoConfig
    """
    samlSsoQuery = requests.get(url, headers=headers, params={"q": query})
    if samlSsoQuery.status_code != 200:
        print("Failed to retrieve SAML SSO Configurations from Salesforce! Exiting.")
        raise samlSsoQuery.reason
    # Use a list comprehension to re-sort the data
    allTsps = [config for config in samlSsoQuery.json()["records"]]

    # Return a tuple of the list of SAML SSO Configs and the Instance URL which is used as the GUID for the instance
    payload = (allTsps, instanceUrl)

    cache["get_salesforce_saml_sso_config"] = payload
    return cache["get_salesforce_saml_sso_config"]

@registry.register_check("salesforce.sso")
def salesforce_sso_saml_sso_config_in_use_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.SingleSignOn.1] Salesforce instances should be configured for Single-Sign On (SSO) by defining a SAML SSO configuration
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_saml_sso_config(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any configs at all
    if not payload[0]:
        assetB64 = None
        samlSsoConfigInUse = False
    else:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(payload[0],default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        samlSsoConfigInUse = True
    # this is a failing check
    if samlSsoConfigInUse is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"salesforce/{payload[1]}/sso/salesforce-saml-ssoc-onfig-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/sso/salesforce-saml-ssoc-onfig-in-use-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Salesforce.SingleSignOn.1] Salesforce instances should be configured for Single-Sign On (SSO) by defining a SAML SSO configuration",
            "Description": f"Salesforce instance {payload[1]} is not configured for Single-Sign On (SSO) due to lacking a SAML SSO configuration. Single sign-on (SSO) is an authentication method that enables users to access multiple applications with one login and one set of credentials. For example, after users log in to your org, they can automatically access all apps from the App Launcher. You can set up your Salesforce org to trust a third-party identity provider to authenticate users. Or you can configure a third-party app to rely on your org for authentication. You can configure your Salesforce org or Experience Cloud site as a service provider with SAML single sign-on (SSO). With this SAML configuration, your users can log in to Salesforce with credentials from an external identity provider. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up SSO for Salesforce, specifically setting up Salesforce as the Service Provider (SP) to be authenticated *into*, refer to the Configure SSO with Salesforce as a SAML Service Provider section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_saml.htm&type=5"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Salesforce",
                "ProviderType": "SaaS",
                "ProviderAccountId": payload[1],
                "AssetRegion": salesforceInstanceLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Salesforce Single Sign-On",
                "AssetComponent": "SAML SSO Configuration"
            },
            "Resources": [
                {
                    "Type": "SalesforceSamlSsoConfig",
                    "Id": f"{payload[1]}/SamlSsoConfig",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
                    "ISO 27001:2013 A.9.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"salesforce/{payload[1]}/sso/salesforce-saml-ssoc-onfig-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/sso/salesforce-saml-ssoc-onfig-in-use-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Salesforce.SingleSignOn.1] Salesforce instances should be configured for Single-Sign On (SSO) by defining a SAML SSO configuration",
            "Description": f"Salesforce instance {payload[1]} is configured for Single-Sign On (SSO) due having at least one SAML SSO configuration.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on setting up SSO for Salesforce, specifically setting up Salesforce as the Service Provider (SP) to be authenticated *into*, refer to the Configure SSO with Salesforce as a SAML Service Provider section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_saml.htm&type=5"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Salesforce",
                "ProviderType": "SaaS",
                "ProviderAccountId": payload[1],
                "AssetRegion": salesforceInstanceLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Salesforce Single Sign-On",
                "AssetComponent": "SAML SSO Configuration"
            },
            "Resources": [
                {
                    "Type": "SalesforceSamlSsoConfig",
                    "Id": f"{payload[1]}/SamlSsoConfig",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
                    "ISO 27001:2013 A.9.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END ??