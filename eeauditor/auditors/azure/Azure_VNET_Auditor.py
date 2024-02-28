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

from azure.mgmt.network import NetworkManagementClient, models
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_azure_vnets(cache: dict, azureCredential, azSubId: str) -> list[models.VirtualNetwork]:
    """
    Returns a list of all Azure Virtual Networks in a Subscription
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_azure_vnets")
    if response:
        return response
    
    vnetList = [vnet for vnet in azNetworkClient.virtual_networks.list_all()]
    if not vnetList or vnetList is None:
        vnetList = []

    cache["get_all_azure_vnets"] = vnetList
    return cache["get_all_azure_vnets"]

def get_all_azure_network_watchers(cache: dict, azureCredential, azSubId: str) -> list[models.NetworkWatcher]:
    """
    Returns a list of all Azure Network Watchers in a Subscription
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_azure_network_watchers")
    if response:
        return response
    
    nwList = [nw for nw in azNetworkClient.network_watchers.list_all()]
    if not nwList or nwList is None:
        nwList = []

    cache["get_all_azure_network_watchers"] = nwList
    return cache["get_all_azure_network_watchers"]

def get_all_azure_nsgs(cache: dict, azureCredential, azSubId: str) -> list[models._models.NetworkSecurityGroup]:
    """
    Returns a list of all NSGs in a Subscription
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_azure_nsgs")
    if response:
        return response
    
    nsgList = [nsg for nsg in azNetworkClient.network_security_groups.list_all()]
    if not nsgList or nsgList is None:
        nsgList = []

    cache["get_all_azure_nsgs"] = nsgList
    return cache["get_all_azure_nsgs"]

def process_resource_group_name(id: str):
    """
    Returns the Resource Group Name from an Azure VM Id
    """
    parts = id.split("/")
    rgIndex = parts.index("resourceGroups") + 1
    
    return parts[rgIndex]

@registry.register_check("azure.vnet")
def azure_vnet_bastion_host_exists_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VNET.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vnet in get_all_azure_vnets(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vnet.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vnet.id)
        azRegion = vnet.location
        vnetName = vnet.name

        # Check if a Bastion Host exists in the Virtual Network
        bastionHostExists = False
        for bastionHost in azNetworkClient.bastion_hosts.list():
            for ipConfig in bastionHost.ip_configurations:
                if vnet.id in ipConfig.subnet.id:
                    bastionHostExists = True
                    break
        
        # this is a failing check
        if bastionHostExists is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vm-bastion-host-exists-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vm-bastion-host-exists-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VNET.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does not have an Azure Bastion Host deployed. Azure Bastion is a fully managed PaaS service that provides secure and seamless RDP and SSH access to your virtual machines directly through the Azure Portal. Azure Bastion is provisioned directly in your Virtual Network (VNet) and supports all VMs in your Virtual Network using SSL without any exposure through public IP addresses. Azure Bastion is provisioned directly in your Virtual Network (VNet) and supports all VMs in your Virtual Network using SSL without any exposure through public IP addresses. Azure Bastion is provisioned directly in your Virtual Network (VNet) and supports all VMs in your Virtual Network using SSL without any exposure through public IP addresses. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To deploy an Azure Bastion Host refer to the Azure Bastion documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/bastion/bastion-create-host-portal"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-21",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.1.2",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.1",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1592",
                        "MITRE ATT&CK T1595"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vm-bastion-host-exists-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vm-bastion-host-exists-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VNET.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does have an Azure Bastion Host deployed.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To deploy an Azure Bastion Host refer to the Azure Bastion documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/bastion/bastion-create-host-portal"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-21",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.1.2",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.1",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1592",
                        "MITRE ATT&CK T1595"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.vnet")
def azure_vnet_ddos_protection_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VNET.2] Azure DDoS Protection should be enabled on Virtual Networks to protect against DDoS attacks
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vnet in get_all_azure_vnets(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vnet.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vnet.id)
        azRegion = vnet.location
        vnetName = vnet.name

        # this is a failing check
        if vnet.enable_ddos_protection is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vnet-ddos-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vnet-ddos-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.VNET.2] Azure DDoS Protection should be enabled on Virtual Networks to protect against DDoS attacks",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does not have Azure DDoS Protection enabled. Distributed denial of service (DDoS) attacks are some of the largest availability and security concerns facing customers that are moving their applications to the cloud. A DDoS attack attempts to exhaust an application's resources, making the application unavailable to legitimate users. DDoS attacks can be targeted at any endpoint that is publicly reachable through the internet. Azure DDoS Protection, combined with application design best practices, provides enhanced DDoS mitigation features to defend against DDoS attacks. It's automatically tuned to help protect your specific Azure resources in a virtual network. Protection is simple to enable on any new or existing virtual network, and it requires no application or resource changes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Azure DDoS Protection and how to enable it refer to the Quickstart: Create and configure Azure DDoS Network Protection using the Azure portal section of the Azure Network DDoS Protection documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.1.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.2",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vnet-ddos-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vnet-ddos-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VNET.2] Azure DDoS Protection should be enabled on Virtual Networks to protect against DDoS attacks",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does have Azure DDoS Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Azure DDoS Protection and how to enable it refer to the Quickstart: Create and configure Azure DDoS Network Protection using the Azure portal section of the Azure Network DDoS Protection documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.1.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.2",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.vnet")
def azure_vnet_network_watcher_deployed_in_vnet_regions_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VNET.3] Azure Network Watcher should be deployed in each region where Virtual Networks are deployed
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    netWatcherRegions = []
    
    for netWatcher in get_all_azure_network_watchers(cache, azureCredential, azSubId):
        if netWatcher.location not in netWatcherRegions:
            netWatcherRegions.append(netWatcher.location)

    for vnet in get_all_azure_vnets(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vnet.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vnet.id)
        azRegion = vnet.location
        vnetName = vnet.name
        if azRegion not in netWatcherRegions:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vnet-network-watcher-deployed-in-vnet-regions-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vnet-network-watcher-deployed-in-vnet-regions-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.VNET.3] Azure Network Watcher should be deployed in each region where Virtual Networks are deployed",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does not have an Azure Network Watcher deployed in the same region. Azure Network Watcher is a regional service that enables you to monitor and diagnose conditions at a network scenario level in, to, and from Azure. Network Watcher provides tools to monitor, diagnose, view metrics, and enable or disable logs for resources in an Azure virtual network. Network Watcher is a regional service and must be deployed in each region where Virtual Networks are deployed. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Azure Network Watchers and how to deployed them refer to the What is Azure Network Watcher? section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vnet.id}/az-vnet-network-watcher-deployed-in-vnet-regions-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vnet.id}/az-vnet-network-watcher-deployed-in-vnet-regions-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VNET.3] Azure Network Watcher should be deployed in each region where Virtual Networks are deployed",
                "Description": f"Virtual Network {vnetName} in Subscription {azSubId} in {azRegion} does have an Azure Network Watcher deployed in the same region.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Azure Network Watchers and how to deployed them refer to the What is Azure Network Watcher? section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Network",
                    "AssetService": "Azure Virtual Network",
                    "AssetComponent": "Virtual Network"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualNetwork",
                        "Id": vnet.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vnetName,
                                "Id": vnet.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.vnet")
def azure_vnet_nsg_flow_logs_laws_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VNET.4] Azure Network Security Groups (NSGs) should have flow logging enabled and sent to an Azure Log Analytics Workspace
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    nsgsLogged = []
    
    for netWatcher in get_all_azure_network_watchers(cache, azureCredential, azSubId):
        rgName = process_resource_group_name(netWatcher.id)
        for flowlog in azNetworkClient.flow_logs.list(rgName,netWatcher.name):
            # ensure the flow log is enabled and flow analytics is enabled
            if (
                flowlog.enabled is True
                and flowlog.flow_analytics_configuration.network_watcher_flow_analytics_configuration.enabled is True
            ):
                nsgsLogged.append(flowlog.target_resource_id)

    # now evaluate the NSGs
    for secgroup in get_all_azure_nsgs(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(secgroup.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        nsgName = secgroup.name
        nsgId = str(secgroup.id)
        azRegion = secgroup.location
        rgName = nsgId.split("/")[4]
        # this is a failing check
        if nsgId not in nsgsLogged:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-laws-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-laws-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.VNET.4] Azure Network Security Groups (NSGs) should have flow logging enabled and sent to an Azure Log Analytics Workspace",
                "Description": f"Network Security Group {nsgName} in Subscription {azSubId} in {azRegion} does not have flow logging enabled and/or sent to an Azure Log Analytics Workspace. Network Security Group (NSG) flow logs provide information that can be used to understand ingress and egress IP traffic on network interfaces. Flow logs are written to an Azure Storage Account as well as an Azure Log Analytics Workspace. Flow logs are not enabled by default and must be configured to send logs to an Azure Log Analytics Workspace. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Network Security Group (NSG) flow logs and how to enable them refer to the Tutorial: Log network traffic to and from a virtual machine using the Azure portal section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-tutorial"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 5.1.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-laws-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-laws-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VNET.4] Azure Network Security Groups (NSGs) should have flow logging enabled and sent to an Azure Log Analytics Workspace",
                "Description": f"Network Security Group {nsgName} in Subscription {azSubId} in {azRegion} does have flow logging enabled and sent to an Azure Log Analytics Workspace.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Network Security Group (NSG) flow logs and how to enable them refer to the Tutorial: Log network traffic to and from a virtual machine using the Azure portal section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-tutorial"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 5.1.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.vnet")
def azure_vnet_nsg_flow_logs_90_day_retention_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VNET.5] Azure Network Security Group (NSG) flow logs should have a retention period of at least 90 days
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    nsgsLogged = []
    
    for netWatcher in get_all_azure_network_watchers(cache, azureCredential, azSubId):
        rgName = process_resource_group_name(netWatcher.id)
        for flowlog in azNetworkClient.flow_logs.list(rgName,netWatcher.name):
            # ensure the flow log is enabled, retention is enabled, and retention is 90 days or more
            if (
                flowlog.enabled is True
                and flowlog.retention_policy.enabled is True
                and flowlog.retention_policy.days >= 90
            ):
                nsgsLogged.append(flowlog.target_resource_id)

    for secgroup in get_all_azure_nsgs(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(secgroup.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        nsgName = secgroup.name
        nsgId = str(secgroup.id)
        azRegion = secgroup.location
        rgName = nsgId.split("/")[4]
        # this is a failing check
        if nsgId not in nsgsLogged:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-90-day-retention-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-90-day-retention-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.VNET.5] Azure Network Security Group (NSG) flow logs should have a retention period of at least 90 days",
                "Description": f"Network Security Group (NSG) flow logs for {nsgName} in Subscription {azSubId} in {azRegion} either does not enable retention or has retention set for less than 90 days. Network Security Group (NSG) flow logs provide information that can be used to understand ingress and egress IP traffic on network interfaces. Flow logs are written to an Azure Storage Account as well as an Azure Log Analytics Workspace. Flow logs are not enabled by default and must be configured to send logs to an Azure Log Analytics Workspace. Flow logs should have a retention period of at least 90 days. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Network Security Group (NSG) flow logs and how to enable them refer to the Quickstart: Configure Azure Network Watcher NSG flow logs using an Azure Resource Manager (ARM) template section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/quickstart-configure-network-security-group-flow-logs-from-arm-template"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-90-day-retention-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{nsgId}/az-vnet-nsg-flow-logs-90-day-retention-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VNET.5] Azure Network Security Group (NSG) flow logs should have a retention period of at least 90 days",
                "Description": f"Network Security Group (NSG) flow logs for {nsgName} in Subscription {azSubId} in {azRegion} retains logs for at least 90 days.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Network Security Group (NSG) flow logs and how to enable them refer to the Quickstart: Configure Azure Network Watcher NSG flow logs using an Azure Resource Manager (ARM) template section of the Azure Networking for Network Watcher documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/network-watcher/quickstart-configure-network-security-group-flow-logs-from-arm-template"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Azure Network Security Group",
                    "AssetComponent": "Network Security Group"
                },
                "Resources": [
                    {
                        "Type": "AzureNetworkSecurityGroup",
                        "Id": nsgId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": nsgName,
                                "Id": nsgId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 6.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??