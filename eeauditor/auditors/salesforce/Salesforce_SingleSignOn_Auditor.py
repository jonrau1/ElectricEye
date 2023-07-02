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
    """[Salesforce.SingleSignOn.1] Salesforce instances should be configured for Single-Sign On (SSO) by defining a SAML SSO configuration"""
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
            "Id": f"salesforce/{payload[1]}/sso/salesforce-saml-sso-config-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/sso/salesforce-saml-sso-config-in-use-check",
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
            "Id": f"salesforce/{payload[1]}/sso/salesforce-saml-sso-config-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/sso/salesforce-saml-sso-config-in-use-check",
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

@registry.register_check("salesforce.sso")
def salesforce_sso_saml_sso_config_req_sig_method_signing_algo_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """[Salesforce.SingleSignOn.2] Salesforce Single-Sign On (SSO) SAML SSO configurations should be configured to use the specified request signature method as the signing algorithm"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_saml_sso_config(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for samlconfig in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(samlconfig,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        samlSsoConfigId = samlconfig["attributes"]["url"].split("/")[6]
        samlSsoConfigName = samlconfig["DeveloperName"]
        # this is a failing check
        if samlconfig["OptionsUseSameDigestAlgoForSigning"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-req-sig-signing-algo-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-req-sig-signing-algo-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.2] Salesforce Single-Sign On (SSO) SAML SSO configurations should be configured to use the specified request signature method as the signing algorithm",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is not configured to use the specified request signature method as the signing algorithm. For SAML configurations where your org or Experience Cloud site acts as a service provider, create a SAML single sign-on (SSO) setting with the information from your identity provider. For configurations created after Spring 2022, the Request Signature Method (RSM) that you select determines the digest algorithm. For example, if you select RSA-SHA256, your digest algorithm is automatically set to SHA256. For configurations created before Spring 2022, the digest algorithm is SHA1 by default. To set the digest algorithm to match the Request Signature Method, select Use digest algorithm based on Request Signature Method. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-req-sig-signing-algo-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-req-sig-signing-algo-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.2] Salesforce Single-Sign On (SSO) SAML SSO configurations should be configured to use the specified request signature method as the signing algorithm",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is configured to use the specified request signature method as the signing algorithm.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("salesforce.sso")
def salesforce_sso_saml_sso_config_sha2_signing_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """[Salesforce.SingleSignOn.3] Salesforce Single-Sign On (SSO) SAML SSO configurations should use Secure Hashing Algorithm Version 2 (SHA-2) as the signing algorithm"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_saml_sso_config(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for samlconfig in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(samlconfig,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        samlSsoConfigId = samlconfig["attributes"]["url"].split("/")[6]
        samlSsoConfigName = samlconfig["DeveloperName"]
        # this is a failing check
        if samlconfig["RequestSignatureMethod"] != "RSA-SHA256":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-sha2-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-sha2-signing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.3] Salesforce Single-Sign On (SSO) SAML SSO configurations should use Secure Hashing Algorithm Version 2 (SHA-2) as the signing algorithm",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is not configured to use Secure Hashing Algorithm Version 2 (SHA-2) as the signing algorithm. RSA-SHA1 is a cryptographic algorithm that combines the RSA encryption algorithm with the SHA-1 hashing algorithm. However, both RSA and SHA-1 are considered to be outdated and potentially vulnerable to certain attacks. On the other hand, RSA-SHA256 combines the RSA algorithm with the SHA-256 hashing algorithm, which produces a 256-bit hash value. SHA-256 is a member of the SHA-2 family, which is considered more secure than SHA-1. RSA-SHA256 provides stronger security than RSA-SHA1 because it uses a more secure hash function and supports larger key sizes. However, ensure that the signing algorithm is supported by upstream SAML versions. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 SC-16",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-sha2-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-sha2-signing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.3] Salesforce Single-Sign On (SSO) SAML SSO configurations should use Secure Hashing Algorithm Version 2 (SHA-2) as the signing algorithm",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is configured to use Secure Hashing Algorithm Version 2 (SHA-2) as the signing algorithm.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 SC-16",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.2.1",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.14.2.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("salesforce.sso")
def salesforce_sso_saml_sso_config_enforce_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """[Salesforce.SingleSignOn.4] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring multi-factor authentication (MFA) enforcement"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_saml_sso_config(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for samlconfig in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(samlconfig,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        samlSsoConfigId = samlconfig["attributes"]["url"].split("/")[6]
        samlSsoConfigName = samlconfig["DeveloperName"]
        # this is a failing check
        if samlconfig["OptionsRequireMfaSaml"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-enforce-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-enforce-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.4] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring multi-factor authentication (MFA) enforcement",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is not configured to enforce multi-factor authentication (MFA). You can configure you SAML SSO configurations to enfroce multi-factor authentication (MFA) via the functionality provided in Salesforce instead of your SSO provider's MFA service. This feature isn't fully enabled until you enable MFA for your users via one of two methods. (1) Enable the 'Require multi-factor authentication (MFA) for all direct UI logins to your Salesforce org' setting. Or (2) assign the 'Multi-Factor Authentication for User Interface Logins' user permission to users who log in via SSO. With this configuration, before users can access Salesforce via their SSO provider, Salesforce prompts them to provide an MFA verification method to confirm their identity. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
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
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-enforce-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-enforce-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.4] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring multi-factor authentication (MFA) enforcement",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is configured to enforce multi-factor authentication (MFA).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring SAML SSO configurations refer to the Step 2: Create a SAML Single Sign-On Setting in Salesforce section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_service_provider_configuration.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
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
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("salesforce.sso")
def salesforce_sso_saml_sso_config_jit_provisioning_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """[Salesforce.SingleSignOn.5] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring Just-in-Time (JIT) user provisioning"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_saml_sso_config(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for samlconfig in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(samlconfig,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        samlSsoConfigId = samlconfig["attributes"]["url"].split("/")[6]
        samlSsoConfigName = samlconfig["DeveloperName"]
        # this is a failing check
        if samlconfig["OptionsUserProvisioning"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-jit-provisioning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-jit-provisioning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.5] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring Just-in-Time (JIT) user provisioning",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is not configured for Just-in-Time (JIT) user provisioning. Use Just-in-Time (JIT) provisioning to automatically create a user account in your Salesforce org the first time a user logs in with a SAML identity provider. JIT provisioning can reduce your workload and save time because you don't provision users or create user accounts in advance. With JIT provisioning, an identity provider passes user information to Salesforce in a SAML 2.0 assertion, which is processed by an Apex JIT handler class. The JIT handler does the heavy lifting of creating and updating user accounts. To let Salesforce manage the JIT handler for you, configure standard JIT provisioning. If you want more control, configure JIT provisioning with a custom handler. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring JIT provisioning for SAML SSO configurations refer to the Enable Just-in-Time Provisioning section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_jit_enable_jit.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
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
                "Id": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-jit-provisioning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/sso/{samlSsoConfigId}/salesforce-saml-sso-config-jit-provisioning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.SingleSignOn.5] Salesforce Single-Sign On (SSO) SAML SSO configurations should be evaluated for configuring Just-in-Time (JIT) user provisioning",
                "Description": f"Salesforce Single-Sign On (SSO) SAML SSO configuration {samlSsoConfigName} in instance {payload[1]} is configured for Just-in-Time (JIT) user provisioning.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring JIT provisioning for SAML SSO configurations refer to the Enable Just-in-Time Provisioning section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.sso_jit_enable_jit.htm&type=5"
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
                        "Id": f"{payload[1]}/SamlSsoConfig/{samlSsoConfigId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "DeveloperName": samlSsoConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
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