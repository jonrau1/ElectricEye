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

def get_file_storage_file_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_file_storage_file_systems")
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

    identityClient = oci.identity.IdentityClient(config)
    fileSysClient = oci.file_storage.FileStorageClient(config)

    aLargeSubsystemOfFileSystems = []

    for compartment in ociCompartments:
        # The File System APIs for top-level objects (File System, Mount Targets) require the Availability Domain specified...for reasons
        for availabilityDomain in identityClient.list_availability_domains(compartment_id=compartment).data:
            availabilityDomain = process_response(availabilityDomain)
            availabilityDomainName = availabilityDomain["name"]
            # First we need to get the File System, list Exports for the File System and then get the configuration of "export options"
            # ElectricEye will combine all of these disparate data points into one asset schema instead of having it in 3 different pieces
            for filesys in fileSysClient.list_file_systems(compartment_id=compartment, availability_domain=availabilityDomainName, lifecycle_state="ACTIVE").data:
                filesys = process_response(filesys)
                filesysId = filesys["id"]
                # ListExports
                for exports in fileSysClient.list_exports(file_system_id=filesysId).data:
                    exports = process_response(exports)
                    exportId = exports["id"]
                    # GetExport gives the "export_options" which are rules and secure configuration settings for NFSv3
                    exportDetail = process_response(fileSysClient.get_export(export_id=exportId).data)["export_options"]
                    # Add options (a list) into the export
                    exports["export_options"] = exportDetail
                # Add the "new" Export with all of the rules into the file system object as a list
                filesys["exports"] = [exports]
                
                aLargeSubsystemOfFileSystems.append(filesys)

    cache["get_file_storage_file_systems"] = aLargeSubsystemOfFileSystems
    return cache["get_file_storage_file_systems"]

def get_file_storage_mount_targets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_file_storage_mount_targets")
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

    identityClient = oci.identity.IdentityClient(config)
    fileSysClient = oci.file_storage.FileStorageClient(config)

    anInsurmountableListOfMountTargets = []

    for compartment in ociCompartments:
        # The File System APIs for top-level objects (File System, Mount Targets) require the Availability Domain specified...for reasons
        for availabilityDomain in identityClient.list_availability_domains(compartment_id=compartment).data:
            availabilityDomain = process_response(availabilityDomain)
            availabilityDomainName = availabilityDomain["name"]
            # Mount Targets - at least the detail we need form it - is just one API call instead of 3 for File Systems...
            for mountTarget in fileSysClient.list_mount_targets(compartment_id=compartment, availability_domain=availabilityDomainName, lifecycle_state="ACTIVE").data:
                mountTarget = process_response(mountTarget)
                
                anInsurmountableListOfMountTargets.append(mountTarget)

    cache["get_file_storage_mount_targets"] = anInsurmountableListOfMountTargets
    return cache["get_file_storage_mount_targets"]

@registry.register_check("oci.filestorage")
def oci_file_storage_file_system_cmk_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.FileStorage.1] File Storage file systems should be encrypted with a Customer-managed Master Encryption Key
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for filesys in get_file_storage_file_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(filesys,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = filesys["compartment_id"]
        filesysId = filesys["id"]
        filesysName = filesys["display_name"]
        availabilityDomain = filesys["availability_domain"]
        lifecycleState = filesys["lifecycle_state"]
        createdAt = str(filesys["time_created"])

        if not filesys["kms_key_id"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.FileStorage.1] File Storage file systems should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle File Storage file system {filesysName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key. File Storage file systems use Oracle-managed keys by default, which leaves all encryption-related matters to Oracle. Optionally, you can encrypt the data in a file system using your own Vault encryption key. Be sure to back up your vaults and keys. Deleting a vault and key otherwise means losing the ability to decrypt any resource or data that the key was used to encrypt. Using a Customer-managed MEK can help satisify regulatory or industry requirements that require you to have control of your own cryptographic material or where you want to ensure different customers or business units use different keys to limit 'data blast radius'. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the Encrypting a File System section of the Oracle Cloud Infrastructure Documentation for File Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/File/Tasks/encrypt-file-system.htm",
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
                    "AssetService": "Oracle File Storage",
                    "AssetComponent": "File System"
                },
                "Resources": [
                    {
                        "Type": "OciFileStorageFileSystem",
                        "Id": filesysId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": filesysName,
                                "Id": filesysId,
                                "AvailabilityDomain": availabilityDomain,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.FileStorage.1] File Storage file systems should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle File Storage file system {filesysName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the Encrypting a File System section of the Oracle Cloud Infrastructure Documentation for File Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/File/Tasks/encrypt-file-system.htm",
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
                    "AssetService": "Oracle File Storage",
                    "AssetComponent": "File System"
                },
                "Resources": [
                    {
                        "Type": "OciFileStorageFileSystem",
                        "Id": filesysId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": filesysName,
                                "Id": filesysId,
                                "AvailabilityDomain": availabilityDomain,
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

# Use Secure Export Options When selected, export options are applied to NFS clients requiring them to use privileged source ports. After creating exports, you can edit the NFS client export options to adjust security for any export.
# https://docs.cloud.oracle.com/iaas/Content/File/Tasks/exportoptions.htm
# for export in exports [] for exportOption in export require_privileged_source_port = True
@registry.register_check("oci.filestorage")
def oci_file_storage_file_system_secure_export_options_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.FileStorage.2] File Storage file systems should enforce secure export options by requiring that NFS clients use privileged source ports
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for filesys in get_file_storage_file_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(filesys,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = filesys["compartment_id"]
        filesysId = filesys["id"]
        filesysName = filesys["display_name"]
        availabilityDomain = filesys["availability_domain"]
        lifecycleState = filesys["lifecycle_state"]
        createdAt = str(filesys["time_created"])

        # Begin evaluation using list comprehensions to see if File Systems actually have Export Sets & Export Options
        # and if they do, ensure that each rule enforces Privileged NFS ports are used
        if filesys["exports"]:
            for export in filesys["exports"]:
                if export["export_options"]:
                    secureExportOption = any(d.get("require_privileged_source_port") == False for d in export["export_options"])
                else:
                    secureExportOption = False
        else:
            secureExportOption = False

        print(f"{filesysName} secure options are {secureExportOption}")

        """if not filesys["kms_key_id"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.FileStorage.2] File Storage file systems should enforce secure export options by requiring that NFS clients use privileged source ports",
                "Description": f"Oracle File Storage file system {filesysName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key. File Storage file systems use Oracle-managed keys by default, which leaves all encryption-related matters to Oracle. Optionally, you can encrypt the data in a file system using your own Vault encryption key. Be sure to back up your vaults and keys. Deleting a vault and key otherwise means losing the ability to decrypt any resource or data that the key was used to encrypt. Using a Customer-managed MEK can help satisify regulatory or industry requirements that require you to have control of your own cryptographic material or where you want to ensure different customers or business units use different keys to limit 'data blast radius'. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the Encrypting a File System section of the Oracle Cloud Infrastructure Documentation for File Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/File/Tasks/encrypt-file-system.htm",
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
                    "AssetService": "Oracle File Storage",
                    "AssetComponent": "File System"
                },
                "Resources": [
                    {
                        "Type": "OciFileStorageFileSystem",
                        "Id": filesysId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": filesysName,
                                "Id": filesysId,
                                "AvailabilityDomain": availabilityDomain,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{filesysId}/oci-file-storage-filesys-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.FileStorage.1] File Storage file systems should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle File Storage file system {filesysName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the Encrypting a File System section of the Oracle Cloud Infrastructure Documentation for File Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/File/Tasks/encrypt-file-system.htm",
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
                    "AssetService": "Oracle File Storage",
                    "AssetComponent": "File System"
                },
                "Resources": [
                    {
                        "Type": "OciFileStorageFileSystem",
                        "Id": filesysId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": filesysName,
                                "Id": filesysId,
                                "AvailabilityDomain": availabilityDomain,
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
            yield finding"""

# All Export Options associated with file system export sets should configure NFS identity squash

# File System Mount Targets should have at least one Network Security Group (NSG) assigned

## END ??