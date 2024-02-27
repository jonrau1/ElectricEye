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

from azure.mgmt.security import SecurityCenter
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_defender_for_cloud_plans(cache: dict, azureCredential, azSubId: str) -> list[dict]:
    """
    Returns a list of all Azure Virtual Networks in a Subscription
    """
    azSecurityCenterClient = SecurityCenter(azureCredential,azSubId)

    response = cache.get("get_all_defender_for_cloud_plans")
    if response:
        return response
    
    planList = [plan for plan in azSecurityCenterClient.pricings.list().as_dict()["value"]]
    if not planList or planList is None:
        planList = []

    cache["get_all_defender_for_cloud_plans"] = planList
    return cache["get_all_defender_for_cloud_plans"]

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_servers_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.1] Microsoft Defender for Cloud for Servers plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "VirtualMachines"
    planFullName = "Microsoft Defender for Cloud for Servers"
    planEnabled = False

    planChecker = [plan for plan in get_all_defender_for_cloud_plans(cache, azureCredential, azSubId) if plan["name"] == planName][0]
    planId = planChecker["id"]
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(planChecker,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    if str(planChecker["pricing_tier"]).lower() != "free":
        planEnabled = True

    # this is a failing check
    if planEnabled is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{planId}/azure-defender-for-cloud-servers-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-servers-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.1] Microsoft Defender for Cloud for Servers plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Servers extends protection to your Windows and Linux machines that run in Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP), and on-premises. Defender for Servers integrates with Microsoft Defender for Endpoint to provide endpoint detection and response (EDR) and other threat protection features. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Servers plan and deployments refer to the Plan your Defender for Servers deployment section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": None,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft Defender for Cloud",
                "AssetComponent": planFullName
            },
            "Resources": [
                {
                    "Type": "MicrosoftDefenderForCloudPlan",
                    "Id": planId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId,
                            "Name": planName,
                            "Id": planId
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.1",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{planId}/azure-defender-for-cloud-servers-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-servers-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.1] Microsoft Defender for Cloud for Servers plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Servers plan and deployments refer to the Plan your Defender for Servers deployment section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": None,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft Defender for Cloud",
                "AssetComponent": planFullName
            },
            "Resources": [
                {
                    "Type": "MicrosoftDefenderForCloudPlan",
                    "Id": planId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId,
                            "Name": planName,
                            "Id": planId
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.1",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_app_services_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.2] Microsoft Defender for Cloud for App Services plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "AppServices"
    planFullName = "Microsoft Defender for Cloud for App Services"
    planEnabled = False

    planChecker = [plan for plan in get_all_defender_for_cloud_plans(cache, azureCredential, azSubId) if plan["name"] == planName][0]
    planId = planChecker["id"]
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(planChecker,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    if str(planChecker["pricing_tier"]).lower() != "free":
        planEnabled = True

    # this is a failing check
    if planEnabled is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{planId}/azure-defender-for-cloud-app-services-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-app-services-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.2] Microsoft Defender for Cloud for App Services plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for App Service uses the scale of the cloud to identify attacks targeting applications running over App Service. Attackers probe web applications to find and exploit weaknesses. Before being routed to specific environments, requests to applications running in Azure go through several gateways, where they're inspected and logged. This data is then used to identify exploits and attackers, and to learn new patterns that will be used later. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for App Services plan and deployments refer to the Overview of Defender for App Service to protect your Azure App Service web apps and APIs section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": None,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft Defender for Cloud",
                "AssetComponent": planFullName
            },
            "Resources": [
                {
                    "Type": "MicrosoftDefenderForCloudPlan",
                    "Id": planId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId,
                            "Name": planName,
                            "Id": planId
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.2",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{planId}/azure-defender-for-cloud-app-services-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-app-services-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.2] Microsoft Defender for Cloud for App Services plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for App Services plan and deployments refer to the Overview of Defender for App Service to protect your Azure App Service web apps and APIs section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": None,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Microsoft Defender for Cloud",
                "AssetComponent": planFullName
            },
            "Resources": [
                {
                    "Type": "MicrosoftDefenderForCloudPlan",
                    "Id": planId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId,
                            "Name": planName,
                            "Id": planId
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.2",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END ??