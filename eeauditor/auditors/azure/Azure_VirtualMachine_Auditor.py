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

from azure.mgmt.compute import ComputeManagementClient, models
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
import datetime
import base64
import json
import re
from check_register import CheckRegister

registry = CheckRegister()

def get_all_azure_vms(cache: dict, azureCredential, azSubId: str) -> list[models.VirtualMachine]:
    """
    Returns a list of all Azure VMs in a Subscription
    """
    azComputeClient = ComputeManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_azure_vms")
    if response:
        return response
    
    vmList = [vm for vm in azComputeClient.virtual_machines.list_all()]
    if not vmList or vmList is None:
        vmList = []

    cache["get_all_azure_vms"] = vmList
    return cache["get_all_azure_vms"]

def get_all_azure_rgs(cache: dict, azureCredential, azSubId: str):
    """
    Returns a list of all Azure Resource Groups in a Subscription
    """
    azResourceClient = ResourceManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_azure_rgs")
    if response:
        return response
    
    rgList = [rg for rg in azResourceClient.resource_groups.list()]
    if not rgList or rgList is None:
        rgList = []

    cache["get_all_azure_rgs"] = rgList
    return cache["get_all_azure_rgs"]

def process_resource_group_name(id: str):
    """
    Returns the Resource Group Name from an Azure VM Id
    """
    parts = id.split("/")
    rgIndex = parts.index("resourceGroups") + 1
    
    return parts[rgIndex]

@registry.register_check("azure.virtual_machines")
def azure_vm_utilizing_managed_disks_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.1] Azure Virtual Machines should utilize Managed Disks for storage
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name

        # Check if the VM is using Managed Disks
        usingManagedDisks = all(
            disk.managed_disk is not None for disk in [vm.storage_profile.os_disk] + vm.storage_profile.data_disks
        )

        # this is a failing check
        if usingManagedDisks is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-utilizing-managed-disks-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-utilizing-managed-disks-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.1] Azure Virtual Machines should utilize Managed Disks for storage",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not utilize Managed Disks for storage. Managed Disks are the new and recommended disk storage offering for use with Azure Virtual Machines for better reliability, availability, and security. Managed Disks provide better reliability for Availability Sets by ensuring that the disks of VMs in an Availability Set are sufficiently isolated from each other to avoid single points of failure. Managed Disks also provide better security by encrypting the disks by default. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To migrate your Azure Virtual Machine instance to Managed Disks refer to the Migrate to Managed Disks documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.2",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-utilizing-managed-disks-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-utilizing-managed-disks-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.1] Azure Virtual Machines should utilize Managed Disks for storage",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does utilize Managed Disks for storage.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To migrate your Azure Virtual Machine instance to Managed Disks refer to the Migrate to Managed Disks documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.2",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_encrypt_os_and_data_disk_with_cmk_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.2] Azure Virtual Machines should encrypt both the OS and Data disks with a Customer Managed Key (CMK)
    """
    azComputeClient = ComputeManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name

        # Check if the OS Disk and all Data Disks have a key
        osDiskEncryptedWithCMK = False
        dataDisksEncryptedWithCMK = False
        # Check OS Disk for CMK Encryption
        if vm.storage_profile.os_disk.managed_disk:
            osDisk = azComputeClient.disks.get(rgName, vm.storage_profile.os_disk.name)
            if osDisk.encryption:
                osDiskEncryptedWithCMK = osDisk.encryption.type == "EncryptionAtRestWithCustomerKey"
        # Check Data Disks for CMK Encryption
        if vm.storage_profile.data_disks:
            dataDisksEncryptedWithCMK = all(
                azComputeClient.disks.get(rgName, disk.name).encryption.type == "EncryptionAtRestWithCustomerKey"
                for disk in vm.storage_profile.data_disks if disk.managed_disk
            )
        # Final condition to check if both OS and Data Disks are encrypted with CMK
        bothEncryptedWithCMK = osDiskEncryptedWithCMK and dataDisksEncryptedWithCMK

        # this is a failing check
        if bothEncryptedWithCMK is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-os-and-disk-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-os-and-disk-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.2] Azure Virtual Machines should encrypt both the OS and Data disks with a Customer Managed Key (CMK)",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not use a CMK for both OS and Data disks. Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Azure Virtual Machine instance should CMKs for both their OS and Data disks refer to the Azure data security and encryption best practices section of the Azure Security Fundamentals guide.",
                        "Url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.3",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-os-and-disk-cmk-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-os-and-disk-cmk-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.2] Azure Virtual Machines should encrypt both the OS and Data disks with a Customer Managed Key (CMK)",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does use a CMK for both OS and Data disks.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Azure Virtual Machine instance should CMKs for both their OS and Data disks refer to the Azure data security and encryption best practices section of the Azure Security Fundamentals guide.",
                        "Url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.3",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_unattached_disks_cmk_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.3] Ensure that unattached disks are encrypted with a Customer Managed Key (CMK)
    """
    azComputeClient = ComputeManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for rg in get_all_azure_rgs(cache, azureCredential, azSubId):
        disks = azComputeClient.disks.list_by_resource_group(rg.name)
        for disk in disks:
            unattachedDisksEncryptedWithCmk = True
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(disk.as_dict(),default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            rgName = rg.name
            azRegion = disk.location
            diskName = disk.name
            if disk.managed_by is None:
                if not (disk.encryption and disk.encryption.type == "EncryptionAtRestWithCustomerKey"):
                    unattachedDisksEncryptedWithCmk = False
                    break

            # this is a failing check
            if unattachedDisksEncryptedWithCmk is False:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{azRegion}/{disk.id}/az-vm-unattached-disks-cmk-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{azRegion}/{disk.id}/az-vm-unattached-disks-cmk-encryption-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Azure.VirtualMachines.3] Ensure that unattached disks are encrypted with a Customer Managed Key (CMK)",
                    "Description": f"Unattached disk {diskName} in Resource Group {rgName} in Subscription {azSubId} in {azRegion} is not encrypted with a CMK. Encrypting the IaaS VM's unattached disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To encrypt your unattached disks with a CMK refer to the Azure data security and encryption best practices section of the Azure Security Fundamentals guide.",
                            "Url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "Azure",
                        "ProviderType": "CSP",
                        "ProviderAccountId": azSubId,
                        "AssetRegion": azRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Azure Disk Storage",
                        "AssetComponent": "Disk"
                    },
                    "Resources": [
                        {
                            "Type": "AzureDisk",
                            "Id": disk.id,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "SubscriptionId": azSubId,
                                    "ResourceGroupName": rgName,
                                    "Region": azRegion,
                                    "Name": diskName,
                                    "Id": disk.id
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.4",
                            "MITRE ATT&CK T1530"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{azRegion}/{disk.id}/az-vm-unattached-disks-cmk-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{azRegion}/{disk.id}/az-vm-unattached-disks-cmk-encryption-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Azure.VirtualMachines.3] Ensure that unattached disks are encrypted with a Customer Managed Key (CMK)",
                    "Description": f"Unattached disk {diskName} in Resource Group {rgName} in Subscription {azSubId} in {azRegion} is encrypted with a CMK.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To encrypt your unattached disks with a CMK refer to the Azure data security and encryption best practices section of the Azure Security Fundamentals guide.",
                            "Url": "https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "Azure",
                        "ProviderType": "CSP",
                        "ProviderAccountId": azSubId,
                        "AssetRegion": azRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Azure Disk Storage",
                        "AssetComponent": "Disk"
                    },
                    "Resources": [
                        {
                            "Type": "AzureDisk",
                            "Id": disk.id,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "SubscriptionId": azSubId,
                                    "ResourceGroupName": rgName,
                                    "Region": azRegion,
                                    "Name": diskName,
                                    "Id": disk.id
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.4",
                            "MITRE ATT&CK T1530"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_monitoring_agent_installed_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.4] Azure Virtual Machines should have the Azure Monitor Agent installed
    """
    azComputeClient = ComputeManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name

        # Check if the VM has the Azure Monitor Agent installed
        monitoringAgentInstalled = False
        extensions = azComputeClient.virtual_machine_extensions.list(rgName, vmName)
        if hasattr(extensions, "value"):
            for ext in extensions.value:
                if "MicrosoftMonitoringAgent" in ext.name:
                    monitoringAgentInstalled = True
                    break

        # this is a failing check
        if monitoringAgentInstalled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-monitoring-agent-installed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-monitoring-agent-installed-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.4] Azure Virtual Machines should have the Azure Monitor Agent installed",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have the Azure Monitor Agent installed. The Azure Monitor Agent collects monitoring data from Azure Virtual Machines and sends it to the Azure Monitor service. The agent collects monitoring data from the guest operating system and workloads of Azure Virtual Machines. The agent is designed to be used with the Azure Monitor service and other monitoring solutions to provide insights into the performance and operation of the applications and workloads running on the virtual machines. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To install the Azure Monitor Agent on your Azure Virtual Machine instance refer to the Azure Monitor Agent documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-monitor/agents/agents-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.5",
                        "MITRE ATT&CK T1553"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-monitoring-agent-installed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-monitoring-agent-installed-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.4] Azure Virtual Machines should have the Azure Monitor Agent installed",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have the Azure Monitor Agent installed.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To install the Azure Monitor Agent on your Azure Virtual Machine instance refer to the Azure Monitor Agent documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-monitor/agents/agents-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 7.5",
                        "MITRE ATT&CK T1553"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
            
@registry.register_check("azure.virtual_machines")
def azure_vm_azure_backup_coverage_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.5] Azure Virtual Machines should have Azure Backup coverage
    """
    azBackupClient = RecoveryServicesBackupClient(azureCredential, azSubId)
    azRecoverySvcClient = RecoveryServicesClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        backupCoverage = False
        vaultFound = False

        for vault in azRecoverySvcClient.vaults.list_by_subscription_id():
            vaultFound = True
            vaultName = vault.name
            resourceGroupName = vault.id.split("/")[4]  # Extracting resource group name from vault ID
            
            # List backup items (protected items) in the vault
            backupItems = azBackupClient.backup_protected_items.list(
                vault_name=vaultName,
                resource_group_name=resourceGroupName,
                filter="backupManagementType eq 'AzureIaasVM' and itemType eq 'VM'"
            )
            
            for item in backupItems:
                if vmId in item.properties.virtual_machine_id:
                    backupCoverage = True
                    break
            
            if backupCoverage:
                break

        # this is a failing check
        if not vaultFound or not backupCoverage:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-azure-backup-coverage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-azure-backup-coverage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.5] Azure Virtual Machines should have Azure Backup coverage",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have Azure Backup coverage. Azure Backup is a scalable solution with zero-infrastructure maintenance that protects your data from security threats and data loss. Azure Backup provides independent and isolated backups to guard against accidental destruction of original data. Azure Backup also provides the ability to restore VMs to a previous state, which is essential for disaster recovery. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To enable Azure Backup coverage for your Azure Virtual Machine instance refer to the Back up an Azure VM from the VM settings section of the Azure Backup documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/backup/backup-azure-vms-first-look-arm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vm.id}/az-vm-azure-backup-coverage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vm.id}/az-vm-azure-backup-coverage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.5] Azure Virtual Machines should have Azure Backup coverage",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have Azure Backup coverage.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To enable Azure Backup coverage for your Azure Virtual Machine instance refer to the Back up an Azure VM from the VM settings section of the Azure Backup documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/backup/backup-azure-vms-first-look-arm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vm.id,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vm.id
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_default_and_guessable_admin_username_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.6] Azure Virtual Machines should not have default or easily guessable administrative usernames
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        # use regex to compare admin username with commonUserNames list
        adminUsername = vm.os_profile.admin_username
        if re.search(r"admin|administrator|sa|root|dbmanager|loginmanager|dbo|guest|public|user", adminUsername, re.IGNORECASE):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-default-and-guessable-admin-username-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-default-and-guessable-admin-username-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.6] Azure Virtual Machines should not have default or easily guessable administrative usernames",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} has a default or easily guessable administrative username. The administrative username for the VM is {adminUsername}. Default and easily guessable administrative usernames are a security risk and should be avoided. Attackers can easily guess the username and use it to attempt to gain unauthorized access to the VM. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot change the username of a Virtual Machine, and ideally should not user password-based authentication, consider migrating to SSH keys or logging in via Microsoft Entra ID password as detailed in the Log in to a Windows virtual machine in Azure by using Microsoft Entra ID including passwordless section of the Microsoft Entra ID documentation.",
                        "Url": "https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-windows"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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
                "Id": f"{azRegion}/{vmId}/az-vm-default-and-guessable-admin-username-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-default-and-guessable-admin-username-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.6] Azure Virtual Machines should not have default or easily guessable administrative usernames",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have a default or easily guessable administrative username. The administrative username for the VM is {adminUsername}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot change the username of a Virtual Machine, and ideally should not user password-based authentication, consider migrating to SSH keys or logging in via Microsoft Entra ID password as detailed in the Log in to a Windows virtual machine in Azure by using Microsoft Entra ID including passwordless section of the Microsoft Entra ID documentation.",
                        "Url": "https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-windows"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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

@registry.register_check("azure.virtual_machines")
def azure_vm_linux_disable_password_authentication_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.7] Azure Virtual Machines with Linux operating systems should have password-based authentication disabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        disablePasswordAuth = True
        try:
            if vm.os_profile.linux_configuration.disable_password_authentication is False:
                disablePasswordAuth = False
        except AttributeError or KeyError:
            disablePasswordAuth = False

        # this is a failing check
        if disablePasswordAuth is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-linux-disable-password-authentication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-linux-disable-password-authentication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.7] Azure Virtual Machines with Linux operating systems should have password-based authentication disabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} has password-based authentication enabled. Password-based authentication should be disabled for Linux Virtual Machines. Disabling password-based authentication is a security best practice and helps to protect your Virtual Machine from unauthorized access. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more issue on Linux Azure Virtual Machine instance connectivity refer to the Connect to a Linux VM section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/linux-vm-connect?tabs=Linux"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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
                "Id": f"{azRegion}/{vmId}/az-vm-linux-disable-password-authentication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-linux-disable-password-authentication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.7] Azure Virtual Machines with Linux operating systems should have password-based authentication disabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have password-based authentication disabled or is a Windows machine.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more issue on Linux Azure Virtual Machine instance connectivity refer to the Connect to a Linux VM section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/linux-vm-connect?tabs=Linux"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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

@registry.register_check("azure.virtual_machines")
def azure_vm_auto_patching_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.8] Azure Virtual Machines should be configured to automatically apply OS patches
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        autoPatching = False
        try:
            # Check for Windows Configuration
            if hasattr(vm.os_profile, "windows_configuration"):
                if (
                    vm.os_profile.windows_configuration is not None 
                    and hasattr(vm.os_profile.windows_configuration, "patch_settings") 
                    and "automatic" in vm.os_profile.windows_configuration.patch_settings.patch_mode.lower()
                ):
                    autoPatching = True
            
            # Check for Linux Configuration
            if hasattr(vm.os_profile, "linux_configuration"):
                if (
                    vm.os_profile.linux_configuration is not None 
                    and hasattr(vm.os_profile.linux_configuration, "patch_settings") 
                    and "automatic" in vm.os_profile.linux_configuration.patch_settings.patch_mode.lower()
                ):
                    autoPatching = True
        except AttributeError or KeyError:
            pass

        # this is a failing check
        if autoPatching is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-auto-patching-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-auto-patching-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.8] Azure Virtual Machines should have automatic OS patching enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have automatic OS patching enabled. Automatic OS patching is a security best practice and helps to protect your Virtual Machine from known vulnerabilities. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To enable automatic OS patching for your Azure Virtual Machine instance refer to the Automatic VM guest patching for Azure VMs section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.18.2.3",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-auto-patching-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-auto-patching-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.8] Azure Virtual Machines should have automatic OS patching enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have automatic OS patching enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To enable automatic OS patching for your Azure Virtual Machine instance refer to the Automatic VM guest patching for Azure VMs section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.18.2.3",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_auto_update_vm_agent_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.9] Azure Virtual Machines should be configured to automatically update the Azure Virtual Machine (VM) Agent
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        autoUpdateVmAgent = False
        try:
            # Check for Windows Configuration
            if hasattr(vm.os_profile, "windows_configuration"):
                remediationText = "To enable automatic VM agent updates for your Windows-based Azure Virtual Machine instance refer to the Azure Windows VM Agent overview section of the Azure Virtual Machines documentation."
                remediationUrl = "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-windows"
                if vm.os_profile.windows_configuration.enable_vm_agent_platform_updates is True:
                    autoUpdateVmAgent = True
            
            # Check for Linux Configuration
            if hasattr(vm.os_profile, "linux_configuration"):
                remediationText = "To enable automatic VM agent updates for your Linux-based Azure Virtual Machine instance refer to the Azure Linux VM Agent overview section of the Azure Virtual Machines documentation."
                remediationUrl = "https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux"
                if vm.os_profile.linux_configuration.enable_vm_agent_platform_updates is True:
                    autoUpdateVmAgent = True
        except AttributeError or KeyError:
            pass

        # this is a failing check
        if autoUpdateVmAgent is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-auto-update-vm-agent-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-auto-update-vm-agent-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.9] Azure Virtual Machines should have automatic VM agent updates enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have automatic VM agent updates enabled. Automatic VM agent updates are a security best practice and help to protect your Virtual Machine from known vulnerabilities in the agent as well as expanding capabilities and ensuring they are up to date. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": remediationText,
                        "Url": remediationUrl
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-auto-update-vm-agent-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-auto-update-vm-agent-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.9] Azure Virtual Machines should have automatic VM agent updates enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have automatic VM agent updates enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": remediationText,
                        "Url": remediationUrl
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.virtual_machines")
def azure_vm_secure_boot_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.10] Azure Virtual Machines that support Trusted Launch should have Secure Boot enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        # this is a failing check
        if (
            vm.security_profile.uefi_settings.secure_boot_enabled is False 
            or vm.security_profile.uefi_settings.secure_boot_enabled is None
        ):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-secure-boot-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-secure-boot-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.10] Azure Virtual Machines should have Secure Boot enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have Secure Boot enabled. At the root of trusted launch is Secure Boot for your VM. Secure Boot, which is implemented in platform firmware, protects against the installation of malware-based rootkits and boot kits. Secure Boot works to ensure that only signed operating systems and drivers can boot. It establishes a 'root of trust' for the software stack on your VM. With Secure Boot enabled, all OS boot components (boot loader, kernel, kernel drivers) require trusted publishers signing. Both Windows and select Linux distributions support Secure Boot. If Secure Boot fails to authenticate that the image is signed by a trusted publisher, the VM fails to boot. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secure Boot and to enable Secure Boot for your Azure Virtual Machine instance (or check if it's supported) refer to the Trusted launch for Azure virtual machines section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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
                "Id": f"{azRegion}/{vmId}/az-vm-secure-boot-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-secure-boot-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.10] Azure Virtual Machines should have Secure Boot enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have Secure Boot enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secure Boot and to enable Secure Boot for your Azure Virtual Machine instance (or check if it's supported) refer to the Trusted launch for Azure virtual machines section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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

@registry.register_check("azure.virtual_machines")
def azure_vm_vtpm_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.VirtualMachines.11] Azure Virtual Machines that support Trusted Launch should have Virtual Trusted Platform Module (vTPM) enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for vm in get_all_azure_vms(cache, azureCredential, azSubId):
        # B64 encode all of the details for the asset
        assetJson = json.dumps(vm.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rgName = process_resource_group_name(vm.id)
        azRegion = vm.location
        vmName = vm.name
        vmId = vm.id

        # this is a failing check
        if (
            vm.security_profile.uefi_settings.v_tpm_enabled is False 
            or vm.security_profile.uefi_settings.v_tpm_enabled is None
        ):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{vmId}/az-vm-vtpm-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-vtpm-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.11] Azure Virtual Machines should have Virtual Trusted Platform Module (vTPM) enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does not have Virtual Trusted Platform Module (vTPM) enabled. vTPM is a virtualized version of a hardware Trusted Platform Module, compliant with the TPM2.0 spec. It serves as a dedicated secure vault for keys and measurements. Trusted launch provides your VM with its own dedicated TPM instance, running in a secure environment outside the reach of any VM. The vTPM enables attestation by measuring the entire boot chain of your VM (UEFI, OS, system, and drivers). Trusted launch uses the vTPM to perform remote attestation through the cloud. Attestations enable platform health checks and for making trust-based decisions. As a health check, trusted launch can cryptographically certify that your VM booted correctly. If the process fails, possibly because your VM is running an unauthorized component, Microsoft Defender for Cloud issues integrity alerts. The alerts include details on which components failed to pass integrity checks. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on vTPM and to enable vTPM for your Azure Virtual Machine instance (or check if it's supported) refer to the Trusted launch for Azure virtual machines section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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
                "Id": f"{azRegion}/{vmId}/az-vm-vtpm-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{vmId}/az-vm-vtpm-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.VirtualMachines.11] Azure Virtual Machines should have Virtual Trusted Platform Module (vTPM) enabled",
                "Description": f"Azure Virtual Machine instance {vmName} in Subscription {azSubId} in {azRegion} does have Virtual Trusted Platform Module (vTPM) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on vTPM and to enable vTPM for your Azure Virtual Machine instance (or check if it's supported) refer to the Trusted launch for Azure virtual machines section of the Azure Virtual Machines documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Azure Virtual Machine",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AzureVirtualMachineInstance",
                        "Id": vmId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": vmName,
                                "Id": vmId
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

# EOF ??