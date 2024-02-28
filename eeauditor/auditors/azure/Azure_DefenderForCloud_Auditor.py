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
    [Azure.DefenderForCloud.1] Microsoft Defender for Servers plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "VirtualMachines"
    planFullName = "Microsoft Defender for Servers"
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
            "Title": "[Azure.DefenderForCloud.1] Microsoft Defender for Servers plan should be enabled on your subscription",
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
                "AssetRegion": "azure-global",
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
            "Title": "[Azure.DefenderForCloud.1] Microsoft Defender for Servers plan should be enabled on your subscription",
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
                "AssetRegion": "azure-global",
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
    [Azure.DefenderForCloud.2] Microsoft Defender for App Services plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "AppServices"
    planFullName = "Microsoft Defender for App Services"
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
            "Title": "[Azure.DefenderForCloud.2] Microsoft Defender for App Services plan should be enabled on your subscription",
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
                "AssetRegion": "azure-global",
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
            "Title": "[Azure.DefenderForCloud.2] Microsoft Defender for App Services plan should be enabled on your subscription",
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
                "AssetRegion": "azure-global",
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

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_databases_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.3] Microsoft Defender for Databases plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = ["SqlServers","SqlServerVirtualMachines","OpenSourceRelationalDatabases","CosmosDbs"]
    planFullName = "Microsoft Defender for Databases"
    planEnabled = True

    planChecker = [plan for plan in get_all_defender_for_cloud_plans(cache, azureCredential, azSubId) if plan["name"] in planName]
    planId = f"/subscriptions/{azSubId}/providers/Microsoft.Security/pricings/Databases"
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(planChecker,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # check these in converse, if any are free or if any of the plans are missing (somehow?), the plan is not enabled
    if set(planName) != set([plan["name"] for plan in planChecker]):
        planEnabled = False
    else:
        for plan in planChecker:
            if str(plan["pricing_tier"]).lower() == "free":
                planEnabled = False
                break

    # this is a failing check
    if planEnabled is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{planId}/azure-defender-for-cloud-databases-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-databases-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.3] Microsoft Defender for Databases plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because at least one of the four plans is on free tier. Defender for Databases in Microsoft Defender for Cloud allows you to protect your entire database estate with attack detection and threat response for the most popular database types in Azure. Defender for Cloud provides protection for the database engines and for data types, according to their attack surface and security risks: Defender for Azure SQL, SQL Server Machines, Open Source Relational DBs, and Azure Cosmos DBs. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Databases plan and deployments refer to the Protect your databases with Defender for Databases section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-databases-plan"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                            "Name": planFullName,
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.3",
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
            "Id": f"{planId}/azure-defender-for-cloud-databases-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-databases-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.3] Microsoft Defender for Databases plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Databases plan and deployments refer to the Protect your databases with Defender for Databases section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-enable-databases-plan"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                            "Name": planFullName,
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.3",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_azure_sql_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.4] Microsoft Defender for Azure SQL plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "SqlServers"
    planFullName = "Microsoft Defender for Azure SQL"
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
            "Id": f"{planId}/azure-defender-for-cloud-azure-sql-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-azure-sql-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.4] Microsoft Defender for Azure SQL plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Azure SQL helps you discover and mitigate potential database vulnerabilities and alerts you to anomalous activities that might be an indication of a threat to your databases. When you enable Microsoft Defender for Azure SQL, all supported resources that exist within the subscription are protected. Future resources created on the same subscription will also be protected. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure SQL plan and deployments refer to the Overview of Microsoft Defender for Azure SQL section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.4",
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
            "Id": f"{planId}/azure-defender-for-cloud-azure-sql-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-azure-sql-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.4] Microsoft Defender for Azure SQL plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure SQL plan and deployments refer to the Overview of Microsoft Defender for Azure SQL section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.4",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_sql_servers_on_vms_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.5] Microsoft Defender for SQL Servers on VMs plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "SqlServerVirtualMachines"
    planFullName = "Microsoft Defender for SQL Servers on Machines"
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
            "Id": f"{planId}/azure-defender-for-cloud-sql-servers-on-vms-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-sql-servers-on-vms-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.5] Microsoft Defender for SQL Servers on VMs plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for SQL Servers on VMs protects your IaaS SQL Servers by identifying and mitigating potential database vulnerabilities and detecting anomalous activities that could indicate threats to your databases. Defender for Cloud populates with alerts when it detects suspicious database activities, potentially harmful attempts to access or exploit SQL machines, SQL injection attacks, anomalous database access, and query patterns. The alerts created by these types of events appear on the alerts reference page. Defender for Cloud uses vulnerability assessment to discover, track, and assist you in the remediation of potential database vulnerabilities. Assessment scans provide an overview of your SQL machines' security state and provide details of any security findings. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for SQL Servers on VMs plan and deployments refer to the Enable Microsoft Defender for SQL servers on machines section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-usage"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.5",
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
            "Id": f"{planId}/azure-defender-for-cloud-sql-servers-on-vms-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-sql-servers-on-vms-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.5] Microsoft Defender for SQL Servers on VMs plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for SQL Servers on VMs plan and deployments refer to the Enable Microsoft Defender for SQL servers on machines section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-usage"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.5",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_open_source_relational_dbs_plan_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.6] Microsoft Defender for Open Source Relational Databases plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "OpenSourceRelationalDatabases"
    planFullName = "Microsoft Defender for Open Source Relational Databases"
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
            "Id": f"{planId}/azure-defender-for-cloud-open-source-relational-dbs-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-open-source-relational-dbs-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.6] Microsoft Defender for Open Source Relational Databases plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Open Source Relational Databases is a security solution that provides threat detection and response for your open-source databases - namely Azure Database for PostgreSQL, MySQL and MariaDB. Defender for Cloud detects anomalous activities indicating unusual and potentially harmful attempts to access or exploit databases. The plan makes it simple to address potential threats to databases without the need to be a security expert or manage advanced security monitoring systems. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Open Source Relational Databases plan and deployments refer to the Overview of Microsoft Defender for open-source relational databases section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.6",
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
            "Id": f"{planId}/azure-defender-for-cloud-open-source-relational-dbs-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-open-source-relational-dbs-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.6] Microsoft Defender for Open Source Relational Databases plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Open Source Relational Databases plan and deployments refer to the Overview of Microsoft Defender for open-source relational databases section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-databases-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.6",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_storage_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.7] Microsoft Defender for Storage plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "StorageAccounts"
    planFullName = "Microsoft Defender for Storage"
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
            "Id": f"{planId}/azure-defender-for-cloud-storage-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-storage-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.7] Microsoft Defender for Storage plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Storage is an Azure-native layer of security intelligence that detects potential threats to your storage accounts. Microsoft Defender for Storage provides comprehensive security by analyzing the data plane and control plane telemetry generated by Azure Blob Storage, Azure Files, and Azure Data Lake Storage services. It uses advanced threat detection capabilities powered by Microsoft Threat Intelligence, Microsoft Defender Antivirus, and Sensitive Data Discovery to help you discover and mitigate potential threats. It helps prevent the three major impacts on your data and workload: malicious file uploads, sensitive data exfiltration, and data corruption. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Storage plan and deployments refer to the Overview of Microsoft Defender for Storage section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.7",
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
            "Id": f"{planId}/azure-defender-for-cloud-storage-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-storage-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.7] Microsoft Defender for Storage plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Storage plan and deployments refer to the Overview of Microsoft Defender for Storage section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.7",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_container_service_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.8] Microsoft Defender for Container Registry plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "ContainerRegistry"
    planFullName = "Microsoft Defender for Container Registry"
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
            "Id": f"{planId}/azure-defender-for-cloud-container-registry-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-container-registry-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.8] Microsoft Defender for Container Registry plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for container registries has been replaced with Microsoft Defender for Containers. If you've already enabled Defender for container registries on a subscription, you can continue to use it. However, you won't get Defender for Containers' improvements and new features. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Containers legacy plan and deployments refer to the Introduction to Microsoft Defender for container registries (deprecated) section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-container-registries-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.8",
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
            "Id": f"{planId}/azure-defender-for-cloud-container-registry-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-container-registry-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.8] Microsoft Defender for Container Registry plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Containers legacy plan and deployments refer to the Introduction to Microsoft Defender for container registries (deprecated) section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-container-registries-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.8",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_cosmosdb_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.9] Microsoft Defender for Azure Cosmos DB plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "CosmosDbs"
    planFullName = "Microsoft Defender for Azure Cosmos DB"
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
            "Id": f"{planId}/azure-defender-for-cloud-cosmosdb-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-cosmosdb-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.9] Microsoft Defender for Azure Cosmos DB plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Azure Cosmos DB detects potential SQL injections, known bad actors based on Microsoft Threat Intelligence, suspicious access patterns, and potential exploitation of your database through compromised identities, or malicious insiders. Defender for Azure Cosmos DB uses advanced threat detection capabilities, and Microsoft Threat Intelligence data to provide contextual security alerts. Those alerts also include steps to mitigate the detected threats and prevent future attacks. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure Cosmos DB plan and deployments refer to the Overview of Microsoft Defender for Azure Cosmos DB section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-defender-for-cosmos"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.9",
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
            "Id": f"{planId}/azure-defender-for-cloud-cosmosdb-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-cosmosdb-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.9] Microsoft Defender for Azure Cosmos DB plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure Cosmos DB plan and deployments refer to the Overview of Microsoft Defender for Azure Cosmos DB section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-defender-for-cosmos"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.9",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_key_vault_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.10] Microsoft Defender for Azure Key Vault plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "KeyVaults"
    planFullName = "Microsoft Defender for Azure Key Vault"
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
            "Id": f"{planId}/azure-defender-for-cloud-key-vault-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-key-vault-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.10] Microsoft Defender for Azure Key Vault plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Key Vault detects unusual and potentially harmful attempts to access or exploit Key Vault accounts. This layer of protection helps you address threats even if you're not a security expert, and without the need to manage third-party security monitoring systems. Azure Key Vault is a cloud service that safeguards encryption keys and secrets like certificates, connection strings, and passwords. Enable Microsoft Defender for Key Vault for Azure-native, advanced threat protection for Azure Key Vault, providing an additional layer of security intelligence. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure Key Vault plan and deployments refer to the Overview of Microsoft Defender for Key Vault section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.10",
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
            "Id": f"{planId}/azure-defender-for-cloud-key-vault-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-key-vault-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.10] Microsoft Defender for Azure Key Vault plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Azure Key Vault plan and deployments refer to the Overview of Microsoft Defender for Key Vault section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.10",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_dns_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.11] Microsoft Defender for Azure DNS (legacy) plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "Dns"
    planFullName = "Microsoft Defender for Azure DNS (legacy)"
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
            "Id": f"{planId}/azure-defender-for-cloud-dns-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-dns-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.11] Microsoft Defender for Azure DNS (legacy) plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for DNS provides an additional layer of protection for resources that use Azure DNS's Azure-provided name resolution capability. From within Azure DNS, Defender for DNS monitors the queries from these resources and detects suspicious activities without the need for any additional agents on your resources. As of August 1 2023, customers with an existing subscription to Defender for DNS can continue to use the service, but new subscribers will receive alerts about suspicious DNS activity as part of Defender for Servers P2. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for DNS legacy plan and deployments refer to the Overview of Microsoft Defender for DNS section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.11",
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
            "Id": f"{planId}/azure-defender-for-cloud-dns-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-dns-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.11] Microsoft Defender for Azure DNS (legacy) plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for DNS legacy plan and deployments refer to the Overview of Microsoft Defender for DNS section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.11",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_resource_manager_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.12] Microsoft Defender for Resource Manager plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "Arm"
    planFullName = "Microsoft Defender for Resource Manager"
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
            "Id": f"{planId}/azure-defender-for-cloud-resource-manager-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-resource-manager-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.12] Microsoft Defender for Resource Manager plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Resource Manager automatically monitors the resource management operations in your organization, whether they're performed through the Azure portal, Azure REST APIs, Azure CLI, or other Azure programmatic clients. Defender for Cloud runs advanced security analytics to detect threats and alerts you about suspicious activity. Azure Resource Manager is the deployment and management service for Azure. It provides a management layer that enables you to create, update, and delete resources in your Azure account. You use management features, like access control, locks, and tags, to secure and organize your resources after deployment. The cloud management layer is a crucial service connected to all your cloud resources. Because of this, it is also a potential target for attackers. Consequently, we recommend security operations teams monitor the resource management layer closely. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Resource Manager plan and deployments refer to the Overview of Microsoft Defender for Resource Manager section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.12",
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
            "Id": f"{planId}/azure-defender-for-cloud-resource-manager-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-resource-manager-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.12] Microsoft Defender for Resource Manager plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Resource Manager plan and deployments refer to the Overview of Microsoft Defender for Resource Manager section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 2.1.12",
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_apis_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.13] Microsoft Defender for APIs plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "Api"
    planFullName = "Microsoft Defender for APIs"
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
            "Id": f"{planId}/azure-defender-for-cloud-apis-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-apis-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.13] Microsoft Defender for APIs plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for APIs is a plan provided by Microsoft Defender for Cloud that offers full lifecycle protection, detection, and response coverage for APIs. Defender for APIs helps you to gain visibility into business-critical APIs. You can investigate and improve your API security posture, prioritize vulnerability fixes, and quickly detect active real-time threats. Defender for APIs currently provides security for APIs published in Azure API Management. Defender for APIs can be onboarded in the Defender for Cloud portal, or within the API Management instance in the Azure portal. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for APIs plan and deployments refer to the About Microsoft Defender for APIs section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
            "Id": f"{planId}/azure-defender-for-cloud-apis-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-apis-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.13] Microsoft Defender for APIs plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is  enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for APIs plan and deployments refer to the About Microsoft Defender for APIs section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-apis-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.defender_for_cloud")
def azure_defender_for_cloud_kubernetes_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.DefenderForCloud.14] Microsoft Defender for Containers plan should be enabled on your subscription
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    planName = "KubernetesService"
    planFullName = "Microsoft Defender for Containers"
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
            "Id": f"{planId}/azure-defender-for-cloud-containers-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-kubernetes-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.14] Microsoft Defender for Kubernetes plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is not enabled in Subscription {azSubId} because it is on the free tier. Microsoft Defender for Containers is a cloud-native solution to improve, monitor, and maintain the security of your containerized assets (Kubernetes clusters, Kubernetes nodes, Kubernetes workloads, container registries, container images and more), and their applications, across multicloud and on-premises environments. Defender for Containers assists you with four core domains of container security: Security posture management, Vulnerability assessment, Run-time threat protection, and deployment & monitoring. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Containers plan and deployments refer to the Overview of Container security in Microsoft Defender for Containers section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
            "Id": f"{planId}/azure-defender-for-cloud-containers-plan-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{planId}/azure-defender-for-cloud-kubernetes-plan-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.DefenderForCloud.14] Microsoft Defender for Kubernetes plan should be enabled on your subscription",
            "Description": f"{planFullName} plan is enabled in Subscription {azSubId} because it is on a paid (standard) tier.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on the Defender for Containers plan and deployments refer to the Overview of Container security in Microsoft Defender for Containers section of the Azure Security Microsoft Defender for Cloud documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
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
                    "MITRE ATT&CK T1210"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

## END ??