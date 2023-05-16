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

def get_instance_configurations(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_instance_configurations")
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

    computeMgmtClient = oci.core.ComputeManagementClient(config)

    aSlightlyConfigurableListOfInstanceConfigurations = []

    for compartment in ociCompartments:
        for template in process_response(computeMgmtClient.list_instance_configurations(compartment_id=compartment).data):
            aSlightlyConfigurableListOfInstanceConfigurations.append(
                process_response(
                    computeMgmtClient.get_instance_configuration(instance_configuration_id=template["id"]).data
                )
            )

    cache["get_instance_configurations"] = aSlightlyConfigurableListOfInstanceConfigurations
    return cache["get_instance_configurations"]

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_vuln_scan_plugin_enabled_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.1] Oracle Cloud Compute Instance Configurations should define that the Vulnerability Scanning agent is enabled on instances
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for config in get_instance_configurations(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(config,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        configId = config["id"]
        configName = config["display_name"]
        compartmentId = config["compartment_id"]
        timeCreated = str(config["time_created"])

        plugins = config["instance_details"]["launch_details"]["agent_config"]["plugins_config"]
        # Check the status / existence of the "Vulnerability Scanning" plugin
        vulnScanPlugin = [param for param in plugins if param["name"] == "Vulnerability Scanning"]
        if vulnScanPlugin:
            if vulnScanPlugin[0]["desired_state"] == "DISABLED":
                vulnScanEnabled = False
            else:
                vulnScanEnabled = True
        else:
            vulnScanEnabled = False

        # Begin finding evaluation
        if vulnScanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-vuln-scan-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-vuln-scan-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.1] Oracle Cloud Compute Instance Configurations should define that the Vulnerability Scanning agent is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that the Vulnerability Scanning agent is enabled on instances. Oracle Cloud Infrastructure Vulnerability Scanning Service helps improve your security posture by routinely checking hosts and container images for potential vulnerabilities. The service gives developers, operations, and security administrators comprehensive visibility into misconfigured or vulnerable resources, and generates reports with metrics and details about these vulnerabilities including remediation information. All Scanning resources and reports are regional, but scan results are also visible as problems in your Cloud Guard global reporting region. Oracle Cloud Infrastructure Vulnerability Scanning Service can help you quickly correct vulnerabilities and exposures, but the service is not a Payment Card Industry (PCI) compliant scanner. Do not use the Scanning service to meet PCI compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the Vulnerability Scanning plugin refer to the Scanning Overview section of the Oracle Cloud Infrastructure Documentation for Management Agents.",
                        "Url": "https://docs.oracle.com/iaas/scanning/using/overview.htm",
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
                    "AssetService": "Oracle Cloud Compute Management",
                    "AssetComponent": "Instance Configuration"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstanceConfiguration",
                        "Id": configId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": configName,
                                "Id": configId,
                                "CreatedAt": timeCreated
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-vuln-scan-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-vuln-scan-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.1] Oracle Cloud Compute Instance Configurations should define that the Vulnerability Scanning agent is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that the Vulnerability Scanning agent is enabled on instances.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the Vulnerability Scanning plugin refer to the Scanning Overview section of the Oracle Cloud Infrastructure Documentation for Management Agents.",
                        "Url": "https://docs.oracle.com/iaas/scanning/using/overview.htm",
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
                    "AssetService": "Oracle Cloud Compute Management",
                    "AssetComponent": "Instance Configuration"
                },
                "Resources": [
                    {
                        "Type": "OciCloudComputeInstanceConfiguration",
                        "Id": configId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": configName,
                                "Id": configId,
                                "CreatedAt": timeCreated
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# [OCI.InstanceConfiguration.2] Oracle Cloud Compute Instance Configurations should define that the OS Management Service Agent agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "OS Management Service Agent" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.3] Oracle Cloud Compute Instance Configurations should define that the Management Agent agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "Management Agent" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.4] Oracle Cloud Compute Instance Configurations should define that the Compute Instance Run Command agent is enabled on instances
# List comprehension on config["instance_details"]["launch_details"]["agent_config"]["plugins_config"] for plugin["name"] == "Compute Instance Run Command" if plugin["desired_state"] == "ENABLED"

# [OCI.InstanceConfiguration.5] Oracle Cloud Compute Instance Configurations should define that public IP addresses are not assigned to instances unless absolutely required
# if config["instance_details"]["launch_details"]["create_vnic_details"]["assign_public_ip"] is True:

# [OCI.InstanceConfiguration.6] Oracle Cloud Compute Instance Configurations should define that instances are protected with Network Security Groups (NSGs)
# if config["instance_details"]["launch_details"]["create_vnic_details"]["nsg_ids"] is None:

# [OCI.InstanceConfiguration.7] Oracle Cloud Compute Instance Configurations should define that instances do not enable Instance Metadata Service version 1 (IMDSv1)
# if config["instance_details"]["launch_details"]["instance_options"]["are_legacy_imds_endpoints_disabled"] is False:

# [OCI.InstanceConfiguration.8] Oracle Cloud Compute Instance Configurations should define that instances enable paravirutalized volume in-transit encryption
# if config["instance_details"]["launch_details"]["is_pv_encryption_in_transit_enabled"] is False:

# [OCI.InstanceConfiguration.9] Oracle Cloud Compute Instance Configurations should define that instances enable Secure Boot
# if config["instance_details"]["launch_details"]["platform_config"]["is_secure_boot_enabled"] is False:

# [OCI.InstanceConfiguration.10] Oracle Cloud Compute Instance Configurations should define that instances enable Measured Boot
# if config["instance_details"]["launch_details"]["platform_config"]["is_measured_boot_enabled"] is False:

# [OCI.InstanceConfiguration.11] Oracle Cloud Compute Instance Configurations should define that instances enable the Trusted Platform Module (TPM)
# if config["instance_details"]["launch_details"]["platform_config"]["is_trusted_platform_module_enabled"] is False:

# [OCI.InstanceConfiguration.12] Oracle Cloud Compute Instance Configurations should define that instances are encrypted with a Customer-managed Master Encryption Key (MEK)
# if config["instance_details"]["launch_details"]["source_details"]["kms_key_id"] is None: