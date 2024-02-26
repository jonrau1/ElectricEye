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

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_storage_accounts(cache: dict, azureCredential, azSubId: str):
    """
    Returns a list of all Azure VMs in a Subscription
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)

    response = cache.get("get_all_storage_accounts")
    if response:
        return response
    
    saList = [sa for sa in azStorageClient.storage_accounts.list()]
    if not saList or saList is None:
        saList = []

    cache["get_all_storage_accounts"] = saList
    return cache["get_all_storage_accounts"]

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_secure_transfer_required_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.1] Azure Storage Accounts should have secure transfer enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        if not sa.enable_https_traffic_only:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.1] Azure Storage Accounts should have secure transfer enabled",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not enforce secure transfers. The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn't support HTTPS for custom domain names, this option is not applied when using a custom domain name. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling secure transfer for Storage Accounts refer to the Security recommendations for Blob storage section of the Azure Storage documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.1] Azure Storage Accounts should have secure transfer enabled",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has secure transfers enforced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling secure transfer for Storage Accounts refer to the Security recommendations for Blob storage section of the Azure Storage documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_infrastructure_encryption_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.2] Azure Storage Accounts should have infrastructure encryption enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        if not sa.encryption:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.2] Azure Storage Accounts should have infrastructure encryption enabled",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have infrastructure encryption enabled. Infrastructure encryption ensures that the data stored in a storage account is encrypted at rest. When infrastructure encryption is enabled, Azure Storage encrypts your data when writing it to Azure Storage and decrypts it when reading it from Azure Storage. Azure Storage automatically encrypts your data when it is persisted to the cloud. Infrastructure encryption is enabled by default and cannot be disabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling infrastructure encryption for Storage Accounts refer to the Security recommendations for Blob storage section of the Azure Storage documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-at-rest"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.2] Azure Storage Accounts should have infrastructure encryption enabled",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has infrastructure encryption enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling infrastructure encryption for Storage Accounts refer to the Security recommendations for Blob storage section of the Azure Storage documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-at-rest"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_sas_policy_exists_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.3] Azure Storage Accounts with Shared Access Signature (SAS) policies should be reviewed to ensure they expire within an hour
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check if there is a sas_policy for the SA
        if sa.sas_policy is not None:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-sas-policy-expire-within-an-hour-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-sas-policy-expire-within-an-hour-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.3] Azure Storage Account Shared Access Signature (SAS) policies should expire within an hour",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has a Shared Access Signature (SAS) policy. SAS policies should expire within an hour to reduce the risk of unauthorized access to your data. When you create a service SAS, you specify the interval for which the SAS is valid. The interval is specified using the start time and the expiry time. The expiry time must be after the start time. The expiry time is an optional parameter. If not specified, the expiry time for the SAS is determined by the end time of the shared access signature. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Shared Access Signatures (SAS) refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-sas-policy-expire-within-an-hour-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-sas-policy-expire-within-an-hour-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.3] Azure Storage Account Shared Access Signature (SAS) policies should expire within an hour",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have a Shared Access Signature (SAS) policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Shared Access Signatures (SAS) refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASS",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_public_acess_disabled_for_sa_with_blob_containers_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.4] Azure Storage Accounts should have public access disabled for Storage Accounts with Blob Containers
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check if the SA has any blobs
        hasBlobs = False
        allowsPublicAccess = True
        # check if the storage account has any blob containers
        saBlobContainers = azStorageClient.blob_services.list(rgName,saName)
        if saBlobContainers:
            hasBlobs = True
        # then, check the properties of the storage account to see if public access is allowed
        saAcctProperties = azStorageClient.storage_accounts.get_properties(rgName,saName)
        if saAcctProperties.allow_blob_public_access is not None and not saAcctProperties.allow_blob_public_access:
            allowsPublicAccess = False
        # this is a failing check
        if hasBlobs and allowsPublicAccess:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-public-access-disabled-for-sa-with-blob-containers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-public-access-disabled-for-sa-with-blob-containers-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.4] Azure Storage Accounts should have public access disabled for Storage Accounts with Blob Containers",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has public access enabled for Blob Containers. Public access to blob data is enabled for the storage account. This means that any anonymous client can read data from the storage account. Public access to blob data is enabled by default when a storage account is created. Public access can be disabled at the storage account level or at the container level. Public access at the container level overrides public access at the storage account level. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on public access to blob data refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.7",
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
                "Id": f"{azRegion}/{saId}/azure-sa-public-access-disabled-for-sa-with-blob-containers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-public-access-disabled-for-sa-with-blob-containers-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.4] Azure Storage Accounts should have public access disabled for Storage Accounts with Blob Containers",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have public access enabled for Blob Containers.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on public access to blob data refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.7",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
                
@registry.register_check("azure.storage_accounts")
def azure_storage_acct_default_network_access_rule_set_to_deny_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.5] Azure Storage Accounts should have the default network access rule set to deny
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check the properties of the storage account to see if the default network access rule is set to deny
        saAcctProperties = azStorageClient.storage_accounts.get_properties(rgName,saName)
        defaultAction = saAcctProperties.network_rule_set.default_action if saAcctProperties.network_rule_set else "Not Set"
        if defaultAction != "Deny":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-default-network-access-rule-set-to-deny-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-default-network-access-rule-set-to-deny-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.5] Azure Storage Accounts should have the default network access rule set to deny",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has the default network access rule set to allow. The default network access rule for the storage account is set to allow. This means that all traffic is allowed by default. This configuration can lead to unauthorized access to your data. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on network access rules refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.8",
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
                "Id": f"{azRegion}/{saId}/azure-sa-default-network-access-rule-set-to-deny-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-default-network-access-rule-set-to-deny-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.5] Azure Storage Accounts should have the default network access rule set to deny",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has the default network access rule set to deny.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on network access rules refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.8",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_trusted_azure_service_access_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.6] Azure Storage Accounts should enable Azure services on the trusted services list to access the storage account
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check the properties of the storage account to see if trusted Azure services are allowed
        saAcctProperties = azStorageClient.storage_accounts.get_properties(rgName,saName)
        networkRules = saAcctProperties.network_rule_set
        if networkRules and "AzureServices" not in networkRules.bypass:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-trusted-azure-service-access-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-trusted-azure-service-access-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.6] Azure Storage Accounts should enable Azure services on the trusted services list to access the storage account",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have trusted Azure services enabled. Trusted Azure services are a set of services that are allowed to access the storage account. By default, all trusted Azure services are allowed to access the storage account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on trusted Azure services refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.9",
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
                "Id": f"{azRegion}/{saId}/azure-sa-trusted-azure-service-access-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-trusted-azure-service-access-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.6] Azure Storage Accounts should enable Azure services on the trusted services list to access the storage account",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has trusted Azure services enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on trusted Azure services refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.9",
                        "MITRE ATT&CK T1530"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_private_endpoints_use_for_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.7] Azure Virtual Network private endpoints should be used for accessing Azure Storage Accounts
    """
    azNetworkClient = NetworkManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        privateEndpoint = False
        # list all private endpoints in the resource group
        for endpoint in azNetworkClient.private_endpoints.list(rgName):
            for conn in endpoint.private_link_service_connections:
                if conn.private_link_service_id == saId:
                    privateEndpoint = True
        
        if not privateEndpoint:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-private-endpoints-use-for-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-private-endpoints-use-for-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.7] Azure Virtual Network private endpoints should be used for accessing Azure Storage Accounts",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have a private endpoint used for accessing the storage account. Private endpoints allow you to securely connect to a storage account over a private endpoint in your virtual network. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on private endpoints refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.10",
                        "MITRE ATT&CK T1537"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-private-endpoints-use-for-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-private-endpoints-use-for-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.7] Azure Virtual Network private endpoints should be used for accessing Azure Storage Accounts",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has a private endpoint used for accessing the storage account.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on private endpoints refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-private-endpoints"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.10",
                        "MITRE ATT&CK T1537"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_soft_delete_enabled_for_blob_storage_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.8] Azure Storage Accounts should have soft delete enabled for blob storage
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        blobProps = azStorageClient.blob_services.get_service_properties(rgName, saName)
        # Check if soft delete for blobs is enabled
        if blobProps.delete_retention_policy.enabled and blobProps.delete_retention_policy.days is not None:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-soft-delete-enabled-for-blob-storage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-soft-delete-enabled-for-blob-storage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.8] Azure Storage Accounts should have soft delete enabled for blob storage",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has soft delete enabled for blob storage.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on soft delete for blob storage refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC8.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.2",
                        "ISO 27001:2013 A.14.2.2",
                        "ISO 27001:2013 A.14.2.3",
                        "ISO 27001:2013 A.14.2.4",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.11",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-soft-delete-enabled-for-blob-storage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-soft-delete-enabled-for-blob-storage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.8] Azure Storage Accounts should have soft delete enabled for blob storage",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not have soft delete enabled for blob storage. Soft delete for blob storage allows you to recover your data when it is inadvertently modified or deleted by an application or other storage account user. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on soft delete for blob storage refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC8.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.2",
                        "ISO 27001:2013 A.14.2.2",
                        "ISO 27001:2013 A.14.2.3",
                        "ISO 27001:2013 A.14.2.4",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.11",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding            

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_use_tls12_for_https_minimum_version_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.9] Azure Storage Accounts should ensure that TLS 1.2 is the minimum TLS version for HTTPS connectivity
    """
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check the properties of the storage account to see if TLS 1.2 is enabled
        saAcctProperties = azStorageClient.storage_accounts.get_properties(rgName,saName)
        minTlsVersion = saAcctProperties.minimum_tls_version
        if minTlsVersion != "TLS1_2":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-use-tls12-for-https-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-use-tls12-for-https-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.9] Azure Storage Accounts should ensure that TLS 1.2 is the minimum TLS version for HTTPS connectivity",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does not enforce TLS 1.2 as the minimum version for HTTPS connectivity. TLS 1.2 is the minimum version of the TLS protocol that should be used for secure connections to the storage account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on TLS 1.2 refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/secure-transfer-azure-storage"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.15"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-use-tls12-for-https-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-use-tls12-for-https-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.9] Azure Storage Accounts should ensure that TLS 1.2 is the minimum TLS version for HTTPS connectivity",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} does enforce TLS 1.2 as the minimum version for HTTPS connectivity.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on TLS 1.2 refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/secure-transfer-azure-storage"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.15"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.storage_accounts")
def azure_storage_acct_90_day_key_rotation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.StorageAccount.10] Azure Storage Accounts should rotate their access keys every 90 days
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        # check that both key rotation days have been in the last 90 days
        keyOneRotation = sa.key_creation_time.key1
        keyTwoRotation = sa.key_creation_time.key2
        # check if the keys have been rotated in the last 90 days
        if keyOneRotation > datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90) and keyTwoRotation > datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90):
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-90-day-key-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-90-day-key-rotation-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.10] Azure Storage Accounts should rotate their access keys every 90 days",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has rotated both access keys within the last 90 days.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on key rotation refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.4",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "MITRE ATT&CK T1098"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{saId}/azure-sa-90-day-key-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{saId}/azure-sa-90-day-key-rotation-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.StorageAccount.10] Azure Storage Accounts should rotate their access keys every 90 days",
                "Description": f"Azure Storage Account {saName} in Subscription {azSubId} in {azRegion} has not rotated both access keys within the last 90 days. When a storage account is created, Azure generates two 512-bit storage access keys which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result from the compromise of these keys. Access keys should be rotated every 90 days to ensure the security of the storage account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on key rotation refer to the Azure Storage documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide"
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
                    "AssetService": "Azure Storage Account",
                    "AssetComponent": "Storage Account",
                },
                "Resources": [
                    {
                        "Type": "AzureStorageAccount",
                        "Id": saId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": saName,
                                "Id": saId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 3.4",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586",
                        "MITRE ATT&CK T1098"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

## END ??