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

API_ROOT = "https://api-us.securitycenter.microsoft.com"

def get_oauth_token(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_oauth_token")
    if response:
        return response

    # Retrieve an OAuth Token for the Security Center APIs
    tokenUrl = f"https://login.microsoftonline.com/{tenantId}/oauth2/token"
    resourceAppIdUri = "https://api.securitycenter.microsoft.com"

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

def get_security_center_recommendations(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_security_center_recommendations")
    if response:
        return response

    # Retrieve the Token from Cache
    headers = {
        "Authorization": f"Bearer {get_oauth_token(cache, tenantId, clientId, clientSecret)}"
    }

    r = requests.get(
        f"{API_ROOT}/api/recommendations",
        headers=headers
    )

    if r.status_code != 200:
        raise r.reason
    else:
        doc = json.loads(r.text)
        # Ignore the patching related reccomendations that will predominately be here - a separate Auditor will handle VM
        listOfRecommendations = [recc for recc in doc["value"] if recc["remediationType"] != "Update"]
        cache["get_security_center_recommendations"] = listOfRecommendations
        return cache["get_security_center_recommendations"]
    
@registry.register_check("m365.recommendations")
def m365_security_center_recommendations_security_controls_for_macos_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.1] Microsoft 365 Defender recommendations for MacOS Security Controls should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reccs = get_security_center_recommendations(cache, tenantId, clientId, clientSecret)

    # Use a list comprehension to scope down what we want to assess based on Active recommendations for a specified category and platform ("relatedComponent")
    reccCategory = "Security controls"
    relatedComponent = "Mac Os"
    checkReccs = [
        recc for recc in reccs if recc["recommendationCategory"] == reccCategory and recc["relatedComponent"] == relatedComponent and recc["status"] == "Active"
    ]
    totalReccs = len(checkReccs)

    # An empty list is a passing check
    if checkReccs:
        assetJson = json.dumps(checkReccs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Use another list comprehension to get the names of the recommendations
        reccNames = [recc["recommendationName"] for recc in checkReccs]
        reccSentence = ", ".join(reccNames)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-security-controls-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-security-controls-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.1] Microsoft 365 Defender recommendations for MacOS Security Controls should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Security Controls require implementation. The following recommendations are still active: {reccSentence}. Cybersecurity weaknesses identified in your organization are mapped to actionable security recommendations and prioritized by their impact. Prioritized recommendations help shorten the time to mitigate or remediate vulnerabilities and drive compliance. Each security recommendation includes actionable remediation steps. To help with task management, the recommendation can also be sent using Microsoft Intune and Microsoft Endpoint Configuration Manager. When the threat landscape changes, the recommendation also changes as it continuously collects information from your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSecurityControls",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-security-controls-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-security-controls-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.1] Microsoft 365 Defender recommendations for MacOS Security Controls should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Security Controls do not require implementation.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": None,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSecurityControls",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("m365.recommendations")
def m365_security_center_recommendations_accounts_for_macos_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.2] Microsoft 365 Defender recommendations for MacOS Accounts should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reccs = get_security_center_recommendations(cache, tenantId, clientId, clientSecret)

    # Use a list comprehension to scope down what we want to assess based on Active recommendations for a specified category and platform ("relatedComponent")
    reccCategory = "Accounts"
    relatedComponent = "Mac Os"
    checkReccs = [
        recc for recc in reccs if recc["recommendationCategory"] == reccCategory and recc["relatedComponent"] == relatedComponent and recc["status"] == "Active"
    ]
    totalReccs = len(checkReccs)

    # An empty list is a passing check
    if checkReccs:
        assetJson = json.dumps(checkReccs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Use another list comprehension to get the names of the recommendations
        reccNames = [recc["recommendationName"] for recc in checkReccs]
        reccSentence = ", ".join(reccNames)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-accounts-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-accounts-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.2] Microsoft 365 Defender recommendations for MacOS Accounts should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Accounts require implementation. The following recommendations are still active: {reccSentence}. Cybersecurity weaknesses identified in your organization are mapped to actionable security recommendations and prioritized by their impact. Prioritized recommendations help shorten the time to mitigate or remediate vulnerabilities and drive compliance. Each security recommendation includes actionable remediation steps. To help with task management, the recommendation can also be sent using Microsoft Intune and Microsoft Endpoint Configuration Manager. When the threat landscape changes, the recommendation also changes as it continuously collects information from your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSAccounts",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-accounts-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-accounts-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.2] Microsoft 365 Defender recommendations for MacOS Accounts should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Accounts do not require implementation.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSAccounts",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("m365.recommendations")
def m365_security_center_recommendations_network_for_macos_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.3] Microsoft 365 Defender recommendations for MacOS Network configurations should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reccs = get_security_center_recommendations(cache, tenantId, clientId, clientSecret)

    # Use a list comprehension to scope down what we want to assess based on Active recommendations for a specified category and platform ("relatedComponent")
    reccCategory = "Network"
    relatedComponent = "Mac Os"
    checkReccs = [
        recc for recc in reccs if recc["recommendationCategory"] == reccCategory and recc["relatedComponent"] == relatedComponent and recc["status"] == "Active"
    ]
    totalReccs = len(checkReccs)

    # An empty list is a passing check
    if checkReccs:
        assetJson = json.dumps(checkReccs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Use another list comprehension to get the names of the recommendations
        reccNames = [recc["recommendationName"] for recc in checkReccs]
        reccSentence = ", ".join(reccNames)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-network-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-network-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.3] Microsoft 365 Defender recommendations for MacOS Network configurations should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Network configurations require implementation. The following recommendations are still active: {reccSentence}. Cybersecurity weaknesses identified in your organization are mapped to actionable security recommendations and prioritized by their impact. Prioritized recommendations help shorten the time to mitigate or remediate vulnerabilities and drive compliance. Each security recommendation includes actionable remediation steps. To help with task management, the recommendation can also be sent using Microsoft Intune and Microsoft Endpoint Configuration Manager. When the threat landscape changes, the recommendation also changes as it continuously collects information from your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSNetwork",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-network-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-network-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.3] Microsoft 365 Defender recommendations for MacOS Network configurations should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Network configurations do not require implementation.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsSNetwork",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("m365.recommendations")
def m365_security_center_recommendations_os_for_macos_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.4] Microsoft 365 Defender recommendations for MacOS OS configurations should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reccs = get_security_center_recommendations(cache, tenantId, clientId, clientSecret)

    # Use a list comprehension to scope down what we want to assess based on Active recommendations for a specified category and platform ("relatedComponent")
    reccCategory = "OS"
    relatedComponent = "Mac Os"
    checkReccs = [
        recc for recc in reccs if recc["recommendationCategory"] == reccCategory and recc["relatedComponent"] == relatedComponent and recc["status"] == "Active"
    ]
    totalReccs = len(checkReccs)

    # An empty list is a passing check
    if checkReccs:
        assetJson = json.dumps(checkReccs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Use another list comprehension to get the names of the recommendations
        reccNames = [recc["recommendationName"] for recc in checkReccs]
        reccSentence = ", ".join(reccNames)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-os-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-os-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.4] Microsoft 365 Defender recommendations for MacOS OS configurations should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS OS configurations require implementation. The following recommendations are still active: {reccSentence}. Cybersecurity weaknesses identified in your organization are mapped to actionable security recommendations and prioritized by their impact. Prioritized recommendations help shorten the time to mitigate or remediate vulnerabilities and drive compliance. Each security recommendation includes actionable remediation steps. To help with task management, the recommendation can also be sent using Microsoft Intune and Microsoft Endpoint Configuration Manager. When the threat landscape changes, the recommendation also changes as it continuously collects information from your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsOsConfiguration",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-os-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-os-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.4] Microsoft 365 Defender recommendations for MacOS OS configurations should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS OS configurations do not require implementation.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsOsConfiguration",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("m365.recommendations")
def m365_security_center_recommendations_network_assessment_for_macos_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.5] Microsoft 365 Defender recommendations for MacOS Network Assessments should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    reccs = get_security_center_recommendations(cache, tenantId, clientId, clientSecret)

    # Use a list comprehension to scope down what we want to assess based on Active recommendations for a specified category and platform ("relatedComponent")
    reccCategory = "Network assessments"
    relatedComponent = "Mac Os"
    checkReccs = [
        recc for recc in reccs if recc["recommendationCategory"] == reccCategory and recc["relatedComponent"] == relatedComponent and recc["status"] == "Active"
    ]
    totalReccs = len(checkReccs)

    # An empty list is a passing check
    if checkReccs:
        assetJson = json.dumps(checkReccs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Use another list comprehension to get the names of the recommendations
        reccNames = [recc["recommendationName"] for recc in checkReccs]
        reccSentence = ", ".join(reccNames)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-network-assessments-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-network-assessments-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.5] Microsoft 365 Defender recommendations for MacOS Network Assessments should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Network Assessments require implementation. The following recommendations are still active: {reccSentence}. Cybersecurity weaknesses identified in your organization are mapped to actionable security recommendations and prioritized by their impact. Prioritized recommendations help shorten the time to mitigate or remediate vulnerabilities and drive compliance. Each security recommendation includes actionable remediation steps. To help with task management, the recommendation can also be sent using Microsoft Intune and Microsoft Endpoint Configuration Manager. When the threat landscape changes, the recommendation also changes as it continuously collects information from your environment. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsNetworkAssessments",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{tenantId}/m365-security-center-recommendations-network-assessments-for-macos-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{tenantId}/m365-security-center-recommendations-network-assessments-for-macos-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[M365.DefenderRecommendations.5] Microsoft 365 Defender recommendations for MacOS Network Assessments should be implemented",
            "Description": f"Microsoft 365 Defender recommendations for M365 Tenant {tenantId} regarding MacOS Network Assessments do not require implementation.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Security recommendations, the logic behind them, remediation guidance, and exception management refer to the Security recommendations section of the Microsoft 365 for Microsoft Defender Vulnerability Management documentation.",
                    "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-security-recommendation?view=o365-worldwide"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "M365",
                "ProviderType": "SaaS",
                "ProviderAccountId": tenantId,
                "AssetRegion": tenantLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft 365 Defender",
                "AssetComponent": "Recommendation"
            },
            "Resources": [
                {
                    "Type": "M365DefenderRecommendation",
                    "Id": f"{tenantId}/Recommendations/MacOsNetworkAssessments",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "TenantId": tenantId,
                            "RecommendationCategory": reccCategory,
                            "RelatedComponent": relatedComponent,
                            "TotalRecommendations": str(totalReccs)
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.IP-7",
                    "NIST CSF V1.1 RS.AN-1",
                    "NIST SP 800-53 Rev. 4 CA-2",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 IR-8",
                    "NIST SP 800-53 Rev. 4 PL-2",
                    "NIST SP 800-53 Rev. 4 PM-6",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 IR-5",
                    "NIST SP 800-53 Rev. 4 PE-6",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC4.2",
                    "AICPA TSC CC5.1",
                    "AICPA TSC CC5.3",
                    "AICPA TSC CC7.3",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.12.4.3",
                    "ISO 27001:2013 A.16.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END ??