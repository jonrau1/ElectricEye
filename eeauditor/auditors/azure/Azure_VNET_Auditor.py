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

from azure.mgmt.network import NetworkManagementClient
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_azure_vnets(cache: dict, azureCredential, azSubId: str):
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

def process_resource_group_name(id: str):
    """
    Returns the Resource Group Name from an Azure VM Id
    """
    parts = id.split("/")
    rgIndex = parts.index("resourceGroups") + 1
    
    return parts[rgIndex]

@registry.register_check("azure.vnet")
def azure_vm_bastion_host_exists_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vnet in get_all_azure_vnets(cache, azureCredential, azSubId):
        print(type(vnet))
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
                "Title": "[Azure.VirtualMachines.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines",
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
                "Title": "[Azure.VirtualMachines.1] Azure Bastion Hosts should be deployed to Virtual Networks to provide secure RDP and SSH access to Azure Virtual Machines",
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

## END ??