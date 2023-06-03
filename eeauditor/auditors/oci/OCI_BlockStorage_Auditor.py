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

import os
import oci
from oci.config import validate_config
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def process_response(responseObject):
    """
    Receives an OCI Python SDK `Response` type (differs by service) and returns a JSON object
    """

    payload = json.loads(
        str(
            responseObject
        )
    )

    return payload

def get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_block_storage_volumes")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    blockStorageClient = oci.core.BlockstorageClient(config)

    aBigBlockyListOfBlockyBois = []

    for compartment in ociCompartments:
        for blockyboi in process_response(blockStorageClient.list_volumes(compartment_id=compartment).data):
            # Get
            blockyBoiBackupPolicyAssignment = process_response(blockStorageClient.get_volume_backup_policy_asset_assignment(asset_id=blockyboi["id"]).data)
            blockyboi["backup_policy"] = blockyBoiBackupPolicyAssignment
            aBigBlockyListOfBlockyBois.append(blockyboi)

    cache["get_block_storage_volumes"] = aBigBlockyListOfBlockyBois
    return cache["get_block_storage_volumes"]

@registry.register_check("oci.blockstorage")
def oci_block_storage_volume_replication_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.BlockStorage.1] Oracle Cloud Block Storage volumes with high availability and enhanced resilience requirements should use replication
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for volume in get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volume,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = volume["compartment_id"]
        volumeId = volume["id"]
        volumeName = volume["display_name"]
        lifecycleState = volume["lifecycle_state"]
        createdAt = str(volume["time_created"])

        if volume["block_volume_replicas"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-replication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-replication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.1] Oracle Cloud Block Storage volumes with high availability and enhanced resilience requirements should use replication",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does not have a replicated volume. The Block Volume service provides you with the capability to perform ongoing automatic asynchronous replication of block volumes and boot volumes to other regions or availability domains within the same region. Cross availability domain replication within the same region is only supported for regions with more than one availability domian. This feature supports disaster recovery, migration, and business expansion scenarios, without requiring volume backups. Replication is typically on required if your data or the application which the block storage volume supports requires high availability or increased resilience and failover. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up replication for Block Storage volumes see the Replicating a Volume section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/volumereplication.htm#volumereplication"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-replication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-replication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.1] Oracle Cloud Block Storage volumes with high availability and enhanced resilience requirements should use replication",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does have a replicated volume.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up replication for Block Storage volumes see the Replicating a Volume section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/volumereplication.htm#volumereplication"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.blockstorage")
def oci_block_storage_volume_auto_tune_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.BlockStorage.2] Oracle Cloud Block Storage volumes should use an auto-tune policy
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for volume in get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volume,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = volume["compartment_id"]
        volumeId = volume["id"]
        volumeName = volume["display_name"]
        lifecycleState = volume["lifecycle_state"]
        createdAt = str(volume["time_created"])

        if volume["is_auto_tune_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-tune-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-tune-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.2] Oracle Cloud Block Storage volumes should use an auto-tune policy",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does not use an auto-tune policy. We do not mean that in a Katy Perry way, your volume can sing just fine. Block Volume provides dynamic performance scaling with autotuning. This feature enables you to configure your volumes so that the service adjusts the performance level automatically to optimize performance. There are two types of dynamic performance scaling with autotuning you can enable for volumes: Performance Based Auto-tuning: When this option is enabled, Block Volume adjusts the volume's performance between the levels you specify, based on the monitored performance for the volume or Detached Volume Auto-tuning: When this option is enabled, Block Volume adjusts the volume's performance level based on whether the volume is attached or detached from an instance. When you enable performance based dynamic scaling with autotuning, you specify the default performance setting (VPUs/GB), which is lowest performance level the volume will be adjusted to when attached to an instance. You also specify the maximum performance level (VPUs/GB), which is the maximum performance level the volume will be adjusted to. Consider auto-tuning when you have higher performance requirements and must scale to match demand without breaching SLIs/SLOs. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up auto-tuning for Block Storage volumes see the Dynamic Performance Scaling section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/autotunevolumeperformance.htm#autotunevolumeperformance"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-tune-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-tune-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.2] Oracle Cloud Block Storage volumes should use an auto-tune policy",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does use an auto-tune policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up auto-tuning for Block Storage volumes see the Dynamic Performance Scaling section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/autotunevolumeperformance.htm#autotunevolumeperformance"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.blockstorage")
def oci_block_storage_volume_use_cmk_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.BlockStorage.3] Oracle Cloud Block Storage volumes should be encrypted with a Customer-managed Master Encryption Key (MEK)
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for volume in get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volume,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = volume["compartment_id"]
        volumeId = volume["id"]
        volumeName = volume["display_name"]
        lifecycleState = volume["lifecycle_state"]
        createdAt = str(volume["time_created"])

        if volume["kms_key_id"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.3] Oracle Cloud Block Storage volumes should be encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key (MEK). All block volumes and boot volumes are encrypted at-rest by Block Volume. There is no option for unencrypted volumes at-rest. Encryption at-rest doesn't impact the performance of the volume and does not incur additional cost. By default, Oracle-provided encryption keys are used for encryption. You have the option to override or specify your own keys stored in the Vault service. Block Volume uses the encryption key configured for the volume for both at-rest and in-transit encryption. You can opt to perform your own custom encryption at the operating system level using third-party software such as devicemapper crypt (dm-crypt), BitLocker Drive Encryption, etc. This encryption is in addition to the standard encryption provided by Oracle for volumes. This means that volumes are double encrypted, first by the software at the operating system level, and then by Oracle using Oracle managed keys. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a customer-managed MEK or using your own custom encryption for Block Storage volumes see the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumeencryption.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.3] Oracle Cloud Block Storage volumes should be encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key (MEK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a customer-managed MEK or using your own custom encryption for Block Storage volumes see the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumeencryption.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.blockstorage")
def oci_block_storage_volume_use_volume_group_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.BlockStorage.4] Oracle Cloud Block Storage volumes should be a member of a Block Volume Group
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for volume in get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volume,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = volume["compartment_id"]
        volumeId = volume["id"]
        volumeName = volume["display_name"]
        lifecycleState = volume["lifecycle_state"]
        createdAt = str(volume["time_created"])

        if volume["volume_group_id"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-volume-group-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-volume-group-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.4] Oracle Cloud Block Storage volumes should be a member of a Block Volume Group",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} is not a member of a Block Volume Group. The Oracle Cloud Infrastructure Block Volume service provides you with the capability to group together multiple volumes in a volume group. A volume group can include both types of volumes, boot volumes, which are the system disks for your compute instances, and block volumes for your data storage. You can use volume groups to create volume group backups and clones that are point-in-time and crash-consistent. This simplifies the process to create time-consistent backups of running enterprise applications that span multiple storage volumes across multiple instances. You can then restore an entire group of volumes from a volume group backup. Similarly, you can also clone an entire volume group in a time-consistent and crash-consistent manner. A deep disk-to-disk and fully isolated clone of a volume group, with all the volumes associated in it, becomes available for use within a matter of seconds. This speeds up the process of creating new environments for development, quality assurance, user acceptance testing, and troubleshooting. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a Volume Group for Block Storage volumes see the Volume Groups section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/volumegroups.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-volume-group-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-use-volume-group-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.4] Oracle Cloud Block Storage volumes should be a member of a Block Volume Group",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} is a member of a Block Volume Group. Great! Now it will not be lonely.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a Volume Group for Block Storage volumes see the Volume Groups section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/volumegroups.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.blockstorage")
def oci_block_storage_volume_automated_backups_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.BlockStorage.5] Oracle Cloud Block Storage volumes be configured to take automated backups
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for volume in get_block_storage_volumes(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volume,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = volume["compartment_id"]
        volumeId = volume["id"]
        volumeName = volume["display_name"]
        lifecycleState = volume["lifecycle_state"]
        createdAt = str(volume["time_created"])

        if not volume["backup_policy"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-backups-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-backups-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.5] Oracle Cloud Block Storage volumes be configured to take automated backups",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} is not configured to take automated backups. The backups feature of the Oracle Cloud Infrastructure Block Volume service lets you make a point-in-time snapshot of the data on a block volume. You can make a backup of a volume when it is attached to an instance or while it is detached. These backups can then be restored to new volumes either immediately after a backup or at a later time that you choose. Backups are encrypted and stored in Oracle Cloud Infrastructure Object Storage, and can be restored as new volumes to any availability domain within the same region they are stored. This capability provides you with a spare copy of a volume and gives you the ability to successfully complete disaster recovery within the same region. Policy-Based Backups are automated scheduled backups as defined by the backup policy assigned to the volume, they can be Oracle defined: Predefined backup policies that have a set backup frequency and retention period. You cannot modify these policies or User defined: Custom backup policies that you create and configure schedules and retention periods for. You can also enable scheduled cross-region automated backups with user defined policies. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a backup and recovery policy for Block Storage volumes see the Overview of Block Volume Backups section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumebackups.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-backups-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{volumeId}/oci-block-storage-volume-auto-backups-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.BlockStorage.5] Oracle Cloud Block Storage volumes be configured to take automated backups",
                "Description": f"Oracle Cloud Block Storage volume {volumeName} in Compartment {compartmentId} in {ociRegionName} is configured to take automated backups.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up a backup and recovery policy for Block Storage volumes see the Overview of Block Volume Backups section of the Oracle Cloud Infrastructure Documentation for Block Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumebackups.htm"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "OciBlockStorageVolume",
                        "Id": volumeId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": volumeName,
                                "Id": volumeId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

## END ??