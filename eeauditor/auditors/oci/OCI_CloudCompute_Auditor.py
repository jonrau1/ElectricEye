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
        Receives an OCI Python SDK `Response` type (differs by service) and responds with a JSON object
        """

        payload = json.loads(str(responseObject))

        return payload

def get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oci_compute_instances")
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

    instanceClient = oci.core.ComputeClient(config)

    instancesList = []

    for compartment in ociCompartments:
        listInstances = instanceClient.list_instances(compartment_id=compartment)
        for instance in listInstances.data:
            processedInstance = process_response(instance)
            instancesList.append(processedInstance)

    cache["get_oci_compute_instances"] = instancesList
    return cache["get_oci_compute_instances"]

@registry.register_check("oci.cloudcompute")
def oci_cloud_compute_secure_boot_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudCompute.1] Cloud Compute instances should have Secure Boot enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for instance in get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = instance["id"]
        instanceName = instance["display_name"]
        compartmentId = instance["compartment_id"]
        imageId = instance["image_id"]
        shape = instance["shape"]
        state = instance["lifecycle_state"]
        # Secure Boot is within "platform_config" which returns None if it's not present (something AWS could learn from)
        # if it is present, check if Confidential Computing ("is_memory_encryption_enabled") is enabled, which means
        # you cannot enable Secure Boot as it supersedes it
        if instance["platform_config"] is None:
            secureBootEnabled = False
        else:
            if instance["platform_config"]["is_memory_encryption_enabled"] is False:
                if instance["platform_config"]["is_secure_boot_enabled"] is False:
                    secureBootEnabled = False
                else:
                    secureBootEnabled = True
            else:
                secureBootEnabled = True

        # Begin finding evaluation
        if secureBootEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.1] Cloud Compute instances should have Secure Boot enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} does not have Secure Boot enabled. Secure Boot is a Unified Extensible Firmware Interface (UEFI) feature that prevents unauthorized boot loaders and operating systems from booting. Secure Boot validates that the signed firmware's signature is correct before booting to prevent rootkits, bootkits, and unauthorized software from running before the operating system loads. Boot components that aren't properly signed are not allowed to run. Rootkits are low-level malware that run in kernel mode. Bootkits replace the system bootloader and system boots with the bootkit instead of the bootloader. Rootkits and bootkits have the same privileges as the operating system and can capture functions like keystrokes and local sign-ins. They can use this information to make unauthorized file transfers and to compromise the operating system. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Secure Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.1] Cloud Compute instances should have Secure Boot enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} either has Secure Boot enabled or utilizes Confidential Computing for in-memory encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Secure Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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

@registry.register_check("oci.cloudcompute")
def oci_cloud_compute_measured_boot_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudCompute.2] Cloud Compute instances should have Measured Boot enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for instance in get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = instance["id"]
        instanceName = instance["display_name"]
        compartmentId = instance["compartment_id"]
        imageId = instance["image_id"]
        shape = instance["shape"]
        state = instance["lifecycle_state"]
        # Measured Boot is within "platform_config" which returns None if it's not present (something AWS could learn from)
        # if it is present, check if Confidential Computing ("is_memory_encryption_enabled") is enabled, which means
        # you cannot enable Measured Boot as it supersedes it
        if instance["platform_config"] is None:
            measuredBootEnabled = False
        else:
            if instance["platform_config"]["is_memory_encryption_enabled"] is False:
                if instance["platform_config"]["is_measured_boot_enabled"] is False:
                    measuredBootEnabled = False
                else:
                    measuredBootEnabled = True
            else:
                measuredBootEnabled = True

        # Begin finding evaluation
        if measuredBootEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-measured-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-measured-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.2] Cloud Compute instances should have Measured Boot enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} does not have Measured Boot enabled. Measured Boot is complementary to Secure Boot. To provide the strongest security, enable both Measured Boot and Secure Boot.  Measured Boot lets you track boot measurements in order to understand what firmware you have and when it changes. When components are updated or reconfigured (for example, during an operating system update), the relevant measurements will change. Additionally some of these measurements will be impacted by the shape and size of the instance. While it is possible to compare these measurements against a set of known measurements, OCI does not currently generate or save known measurements. However, the measurements can be used to attest that OVMF UEFI firmware has not changed since the instance was deployed. Measured Boot enhances boot security by storing measurements of boot components, such as bootloaders, drivers, and operating systems. The first time you boot a shielded instance, Measured Boot uses the initial measurements to create a baseline. The baseline measurements are also known as golden measurements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Measured Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-measured-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-measured-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.2] Cloud Compute instances should have Measured Boot enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} either has Measured Boot enabled or utilizes Confidential Computing for in-memory encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Measured Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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
                "Workflow": {"Status": "ARCHIVED"},
                "RecordState": "RESOLVED"
            }
            yield finding

@registry.register_check("oci.cloudcompute")
def oci_cloud_compute_tpm_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.CloudCompute.3] Cloud Compute instances should have the Trusted Platform Module enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for instance in get_oci_compute_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = instance["id"]
        instanceName = instance["display_name"]
        compartmentId = instance["compartment_id"]
        imageId = instance["image_id"]
        shape = instance["shape"]
        state = instance["lifecycle_state"]
        # Measured Boot is within "platform_config" which returns None if it's not present (something AWS could learn from)
        # if it is present, check if Confidential Computing ("is_memory_encryption_enabled") is enabled, which means
        # you cannot enable Measured Boot as it supersedes it
        if instance["platform_config"] is None:
            tpmEnabled = False
        else:
            if instance["platform_config"]["is_memory_encryption_enabled"] is False:
                if instance["platform_config"]["is_trusted_platform_module_enabled"] is False:
                    tpmEnabled = False
                else:
                    tpmEnabled = True
            else:
                tpmEnabled = True

        # Begin finding evaluation
        if tpmEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-tpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-tpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.3] Cloud Compute instances should have the Trusted Platform Module enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} does not have the Trusted Platform Module enabled. The Trusted Platform Module (TPM) is a specialized security chip used by Measured Boot to store the boot measurements. On VM instances, when you enable Measured Boot, the Trusted Platform Module is automatically enabled, because the TPM is required by Measured Boot. Measurements taken by Measured Boot are stored in Platform Configuration Registers (PCRs) inside the TPM. A PCR is a memory location in the TPM used to hold a value that summarizes all the measurement results that were presented to it in the order they were presented. Windows Defender Credential Guard uses the TPM to protect Virtualization-Based Security (VBS) encryption keys. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have the Trusted Platform Module enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-tpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{instanceId}/oci-instance-tpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.CloudCompute.3] Cloud Compute instances should have the Trusted Platform Module enabled",
                "Description": f"Oracle Cloud Compute instance {instanceName} in Compartment {compartmentId} in {ociRegionName} either has the Trusted Platform Module enabled or utilizes Confidential Computing for in-memory encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have the Trusted Platform Module enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Oracle Cloud Compute",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstance",
                        "Id": instanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": instanceName,
                                "Id": instanceId,
                                "ImageId": imageId,
                                "Shape": shape,
                                "LifecycleState": state
                            }
                        },
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

# END ??