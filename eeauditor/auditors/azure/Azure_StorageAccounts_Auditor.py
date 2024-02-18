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
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        if not sa.enable_https_traffic_only:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
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
                "Id": f"{azSubId}/{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{saId}/azure-sa-secure-transfer-required-enabled-check",
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
    azStorageClient = StorageManagementClient(azureCredential,azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sa in get_all_storage_accounts(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sa,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        saName = sa.name
        saId = sa.id
        azRegion = sa.location
        rgName = saId.split("/")[4]
        if not sa.encryption:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
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
                "Id": f"{azSubId}/{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{saId}/azure-sa-infrastructure-encryption-enabled-check",
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