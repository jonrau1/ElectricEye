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
def oci_cloud_compute_instance_config_vuln_scan_plugin_enabled_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
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
        pluginChecker = [param for param in plugins if param["name"] == "Vulnerability Scanning"]
        if pluginChecker:
            if pluginChecker[0]["desired_state"] == "DISABLED":
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
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
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
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_os_mgmt_service_plugin_enabled_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.2] Oracle Cloud Compute Instance Configurations should define that the OS Management Service Agent plugin is enabled on instances
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
        pluginChecker = [param for param in plugins if param["name"] == "OS Management Service Agent"]
        if pluginChecker:
            if pluginChecker[0]["desired_state"] == "DISABLED":
                osMgmtServiceAgentEnabled = False
            else:
                osMgmtServiceAgentEnabled = True
        else:
            osMgmtServiceAgentEnabled = False

        # Begin finding evaluation
        if osMgmtServiceAgentEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-os-mgmt-service-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-os-mgmt-service-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.2] Oracle Cloud Compute Instance Configurations should define that the OS Management Service Agent plugin is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that the OS Management Service Agent plugin is enabled on instances. The Oracle Cloud Infrastructure OS Management service allows you to manage and monitor updates and patches for the operating system environments on your Oracle Cloud instances, including instances managed by the OS Management Oracle Autonomous Linux service. OS Management also provides options for discovering and monitoring resources on your instances. OS Management uses the OS Management Service Agent plugin for managing and applying updates. The Oracle Cloud Agent manages the OS Management Service Agent plugin. For Linux instances, OS Management provides a search facility that you can use to check individual packages. Using this search facility, you can check for available updates. You can also use this facility to perform actions for managing Linux packages, such as installing, removing, and updating packages on managed instances and managed instance groups. For Windows instances, OS Management provides actions for installing Windows updates on managed instances and managed instance groups. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the OS Management Service Agent plugin refer to the Getting Started with OS Management section of the Oracle Cloud Infrastructure Documentation for OS Management.",
                        "Url": "https://docs.oracle.com/en-us/iaas/os-management/osms/osms-getstarted.htm#osms-enable-existing-instance",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-os-mgmt-service-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-os-mgmt-service-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.2] Oracle Cloud Compute Instance Configurations should define that the OS Management Service Agent plugin is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that the OS Management Service Agent plugin is enabled on instances.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the OS Management Service Agent plugin refer to the Getting Started with OS Management section of the Oracle Cloud Infrastructure Documentation for OS Management.",
                        "Url": "https://docs.oracle.com/en-us/iaas/os-management/osms/osms-getstarted.htm#osms-enable-existing-instance",
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_mgmt_plugin_enabled_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.3] Oracle Cloud Compute Instance Configurations should define that the Management Agent plugin is enabled on instances
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
        pluginChecker = [param for param in plugins if param["name"] == "Management Agent"]
        if pluginChecker:
            if pluginChecker[0]["desired_state"] == "DISABLED":
                mgmtAgentEnabled = False
            else:
                mgmtAgentEnabled = True
        else:
            mgmtAgentEnabled = False

        # Begin finding evaluation
        if mgmtAgentEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-mgmt-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-mgmt-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.3] Oracle Cloud Compute Instance Configurations should define that the Management Agent plugin is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that the Management Agent plugin is enabled on instances. Oracle Cloud Agent is a lightweight process that manages plugins running on compute instances. Plugins collect performance metrics, install OS updates, and perform other instance management tasks. To use plugins on an instance, the Oracle Cloud Agent software must be installed on the instance, the plugins must be enabled, and the plugins must be running. You might need to perform additional configuration tasks before you can use certain plugins. The Management Agent collects data from resources such as OSs, applications, and infrastructure resources for Oracle Cloud Infrastructure services that are integrated with Management Agent. Data can include observability, log, configuration, capacity, and health data. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use the Management Agent refer to the Upgrading to the Deploy Management Agents on Compute Instances section of the Oracle Cloud Infrastructure Documentation for Management Agents.",
                        "Url": "https://docs.oracle.com/iaas/management-agents/doc/management-agents-oracle-cloud-agent.html"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-mgmt-plugin-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-mgmt-plugin-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.3] Oracle Cloud Compute Instance Configurations should define that the Management Agent plugin is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that the Management Agent plugin is enabled on instances.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use the Management Agent refer to the Upgrading to the Deploy Management Agents on Compute Instances section of the Oracle Cloud Infrastructure Documentation for Management Agents.",
                        "Url": "https://docs.oracle.com/iaas/management-agents/doc/management-agents-oracle-cloud-agent.html"
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_run_command_agent_enabled_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.4] Oracle Cloud Compute Instance Configurations should define that the Compute Instance Run Command agent is enabled on instances
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
        pluginChecker = [param for param in plugins if param["name"] == "Compute Instance Run Command"]
        if pluginChecker:
            if pluginChecker[0]["desired_state"] == "DISABLED":
                computeInstanceRunCmdAgent = False
            else:
                computeInstanceRunCmdAgent = True
        else:
            computeInstanceRunCmdAgent = False

        # Begin finding evaluation
        if computeInstanceRunCmdAgent is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-run-command-agent-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-run-command-agent-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.4] Oracle Cloud Compute Instance Configurations should define that the Compute Instance Run Command agent is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that the Compute Instance Run Command agent is enabled on instances. You can remotely configure, manage, and troubleshoot compute instances by running scripts within the instance using the run command feature. For example, the run command feature can help you automate tasks such as configuring secondary virtual network interface cards (VNICs), joining instances to an identity provider, troubleshooting SSH connectivity, or responding to cross-region disaster recovery scenarios. You can run commands on an instance even when the instance does not have SSH access or open inbound ports. The run command feature uses the Compute Instance Run Command plugin that is managed by the Oracle Cloud Agent software.  Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use the Compute Instance Run Command Agent refer to the Oracle Cloud Agent section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/manage-plugins.htm#manage-plugins"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-run-command-agent-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-run-command-agent-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.4] Oracle Cloud Compute Instance Configurations should define that the Compute Instance Run Command agent is enabled on instances",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that the Compute Instance Run Command agent is enabled on instances.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use the Compute Instance Run Command Agent refer to the Oracle Cloud Agent section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/manage-plugins.htm#manage-plugins"
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_public_instance_assigned_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.5] Oracle Cloud Compute Instance Configurations should define that public IP addresses are not assigned to instances unless absolutely required
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

        if config["instance_details"]["launch_details"]["create_vnic_details"]["assign_public_ip"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-public-ip-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-public-ip-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.5] Oracle Cloud Compute Instance Configurations should define that public IP addresses are not assigned to instances unless absolutely required",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that public IP addresses are assigned to instances. A public IP address is an IPv4 address that is reachable from the internet. If a resource in your tenancy needs to be directly reachable from the internet, it must have a public IP address. Depending on the type of resource, there might be other requirements You can assign a public IP address to an instance to enable communication with the internet. The instance is assigned a public IP address from the Oracle Cloud Infrastructure address pool. The assignment is actually to a private IP object on the instance. The VNIC that the private IP is assigned to must be in a public subnet. A given instance can have multiple secondary VNICs, and a given VNIC can have multiple secondary private IPs. So you can assign a given instance multiple public IPs across one or more VNICs if you like. While there are many legitimate use cases for having a publicly reachable instance, consider using VPNs, Load Balancers, and Reverse Proxies to protect your resources - without additional security controls adversaries can perform recon and follow-on nefarious actions on your cloud infrastructure. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should not have a Public IP assigned refer to the Public IP Addresses section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#Public_IP_Addresses"
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-public-ip-assigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-public-ip-assigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.5] Oracle Cloud Compute Instance Configurations should define that public IP addresses are not assigned to instances unless absolutely required",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that public IP addresses are assigned to instances.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should not have a Public IP assigned refer to the Public IP Addresses section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingpublicIPs.htm#Public_IP_Addresses"
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_use_nsgs_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.6] Oracle Cloud Compute Instance Configurations should define that instances are protected with Network Security Groups (NSGs)
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

        if config["instance_details"]["launch_details"]["create_vnic_details"]["nsg_ids"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.6] Oracle Cloud Compute Instance Configurations should define that instances are protected with Network Security Groups (NSGs)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances are protected with Network Security Groups (NSGs). NSGs act as a virtual firewall for your compute instances and other kinds of resources. An NSG consists of a set of ingress and egress security rules that apply only to a set of VNICs of your choice in a single VCN (for example: all the compute instances that act as web servers in the web tier of a multi-tier application in your VCN). NSG security rules function the same as security list rules. However, for an NSG security rule's source (for ingress rules) or destination (for egress rules), you can specify an NSG instead of a CIDR. This means you can easily write security rules to control traffic between two NSGs in the same VCN, or traffic within a single NSG. See Parts of a Security Rule. Unlike with security lists, the VCN does not have a default NSG. Also, each NSG you create is initially empty. It has no default security rules. A network security group (NSG) provides a virtual firewall for a set of cloud resources that all have the same security posture. For example: a group of compute instances that all perform the same tasks and thus all need to use the same set of ports. If you have resources with different security postures in the same VCN, you can write NSG security rules to control traffic between the resources with one posture versus another. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have a NSG assigned refer to the Network Security Groups section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm#support",
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-use-nsgs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-use-nsgs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.6] Oracle Cloud Compute Instance Configurations should define that instances are protected with Network Security Groups (NSGs)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances are protected with Network Security Groups (NSGs).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have a NSG assigned refer to the Network Security Groups section of the Oracle Cloud Infrastructure Documentation for Networks.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm#support",
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_disable_imdsv1_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.7] Oracle Cloud Compute Instance Configurations should define that instances disable Instance Metadata Service version 1 (IMDSv1)
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

        if config["instance_details"]["launch_details"]["instance_options"]["are_legacy_imds_endpoints_disabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-disable-imdsv1-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-disable-imdsv1-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.7] Oracle Cloud Compute Instance Configurations should define that instances disable Instance Metadata Service version 1 (IMDSv1)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances disable Instance Metadata Service version 1 (IMDSv1). The instance metadata service (IMDS) provides information about a running instance, including a variety of details about the instance, its attached virtual network interface cards (VNICs), its attached multipath-enabled volume attachments, and any custom metadata that you define. IMDS also provides information to cloud-init that you can use for various system initialization tasks. The instance metadata service is available in two versions, version 1 and version 2. IMDSv2 offers increased security compared to v1. All requests to the v2 endpoints must include an authorization header. Requests that do not include the authorization header are rejected and requests that are forwarded using the HTTP headers 'Forwarded', 'X-Forwarded-For', or 'X-Forwarded-Host' are also rejected. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should disable access to IMDSv1 endpoints refer to the Upgrading to the Instance Metadata Service v2 section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm#upgrading-v2"
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
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-disable-imdsv1-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-disable-imdsv1-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.7] Oracle Cloud Compute Instance Configurations should define that instances disable Instance Metadata Service version 1 (IMDSv1)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances disable Instance Metadata Service version 1 (IMDSv1).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should disable access to IMDSv1 endpoints refer to the Upgrading to the Instance Metadata Service v2 section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm#upgrading-v2"
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
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_pv_volume_in_transit_encryption_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.8] Oracle Cloud Compute Instance Configurations should define that instances enable paravirutalized volume in-transit encryption
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

        if config["instance_details"]["launch_details"]["is_pv_encryption_in_transit_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-pv-volume-in-transit-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-pv-volume-in-transit-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.8] Oracle Cloud Compute Instance Configurations should define that instances enable paravirutalized volume in-transit encryption",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances enable paravirutalized volume in-transit encryption. All the data moving between the instance and the block volume is transferred over an internal and highly secure network. If you have specific compliance requirements related to the encryption of the data while it is moving between the instance and the block volume, the Block Volume service provides the option to enable in-transit encryption for paravirtualized volume attachments on virtual machine (VM) instances. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have volume in-transit encryption enabled refer to the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm#BlockVolumeEncryption",
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
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-pv-volume-in-transit-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-pv-volume-in-transit-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.8] Oracle Cloud Compute Instance Configurations should define that instances enable paravirutalized volume in-transit encryption",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances enable paravirutalized volume in-transit encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have volume in-transit encryption enabled refer to the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm#BlockVolumeEncryption",
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
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_enable_secure_boot_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.9] Oracle Cloud Compute Instance Configurations should define that instances enable Secure Boot
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

        if config["instance_details"]["launch_details"]["platform_config"]["is_secure_boot_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.9] Oracle Cloud Compute Instance Configurations should define that instances enable Secure Boot",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances enable Secure Boot. Secure Boot is a Unified Extensible Firmware Interface (UEFI) feature that prevents unauthorized boot loaders and operating systems from booting. Secure Boot validates that the signed firmware's signature is correct before booting to prevent rootkits, bootkits, and unauthorized software from running before the operating system loads. Boot components that aren't properly signed are not allowed to run. Rootkits are low-level malware that run in kernel mode. Bootkits replace the system bootloader and system boots with the bootkit instead of the bootloader. Rootkits and bootkits have the same privileges as the operating system and can capture functions like keystrokes and local sign-ins. They can use this information to make unauthorized file transfers and to compromise the operating system. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Secure Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-secure-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-secure-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.9] Oracle Cloud Compute Instance Configurations should define that instances enable Secure Boot",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances enable Secure Boot.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Secure Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_enable_measured_boot_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.10] Oracle Cloud Compute Instance Configurations should define that instances enable Measured Boot
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

        if config["instance_details"]["launch_details"]["platform_config"]["is_measured_boot_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-measured-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-measured-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.10] Oracle Cloud Compute Instance Configurations should define that instances enable Measured Boot",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances enable Measured Boot. Measured Boot is complementary to Secure Boot. To provide the strongest security, enable both Measured Boot and Secure Boot.  Measured Boot lets you track boot measurements in order to understand what firmware you have and when it changes. When components are updated or reconfigured (for example, during an operating system update), the relevant measurements will change. Additionally some of these measurements will be impacted by the shape and size of the instance. While it is possible to compare these measurements against a set of known measurements, OCI does not currently generate or save known measurements. However, the measurements can be used to attest that OVMF UEFI firmware has not changed since the instance was deployed. Measured Boot enhances boot security by storing measurements of boot components, such as bootloaders, drivers, and operating systems. The first time you boot a shielded instance, Measured Boot uses the initial measurements to create a baseline. The baseline measurements are also known as golden measurements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Measured Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-measured-boot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-measured-boot-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.10] Oracle Cloud Compute Instance Configurations should define that instances enable Measured Boot",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances enable Measured Boot.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have Measured Boot enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_enable_tpm_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.11] Oracle Cloud Compute Instance Configurations should define that instances enable the Trusted Platform Module (TPM)
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

        if config["instance_details"]["launch_details"]["platform_config"]["is_trusted_platform_module_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-tpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-tpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.11] Oracle Cloud Compute Instance Configurations should define that instances enable the Trusted Platform Module (TPM)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances enable the Trusted Platform Module (TPM). The Trusted Platform Module (TPM) is a specialized security chip used by Measured Boot to store the boot measurements. On VM instances, when you enable Measured Boot, the Trusted Platform Module is automatically enabled, because the TPM is required by Measured Boot. Measurements taken by Measured Boot are stored in Platform Configuration Registers (PCRs) inside the TPM. A PCR is a memory location in the TPM used to hold a value that summarizes all the measurement results that were presented to it in the order they were presented. Windows Defender Credential Guard uses the TPM to protect Virtualization-Based Security (VBS) encryption keys. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have the Trusted Platform Module enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-tpm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-config-enable-tpm-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.11] Oracle Cloud Compute Instance Configurations should define that instances enable the Trusted Platform Module (TPM)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances enable the Trusted Platform Module (TPM).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should have the Trusted Platform Module enabled refer to the Using Shielded Instances section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Compute/References/shielded-instances.htm#use"
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

@registry.register_check("oci.instanceconfiguration")
def oci_cloud_compute_instance_config_use_vault_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.InstanceConfiguration.12] Oracle Cloud Compute Instance Configurations should define that instances are encrypted with a Customer-managed Master Encryption Key (MEK)
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

        if config["instance_details"]["launch_details"]["source_details"]["kms_key_id"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-use-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-use-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.12] Oracle Cloud Compute Instance Configurations should define that instances are encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does not define that instances are encrypted with a Customer-managed Master Encryption Key (MEK). The Oracle Cloud Infrastructure Block Volume service always encrypts all block volumes, boot volumes, and volume backups at rest by using the Advanced Encryption Standard (AES) algorithm with 256-bit encryption. By default all volumes and their backups are encrypted using the Oracle-provided encryption keys. Each time a volume is cloned or restored from a backup the volume is assigned a new unique encryption key. You have the option to encrypt all of your volumes and their backups using the keys that you own and manage using the Vault service. If you do not configure a volume to use the Vault service or you later unassign a key from the volume, the Block Volume service uses the Oracle-provided encryption key instead. This applies to both encryption at-rest and paravirtualized in-transit encryption. Using Customer-managed keys gives you control over rotation, usage, and accountability. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use a Customer-managed MEK refer to the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm#BlockVolumeEncryption"
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-use-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{configId}/oci-instance-use-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.InstanceConfiguration.12] Oracle Cloud Compute Instance Configurations should define that instances are encrypted with a Customer-managed Master Encryption Key (MEK)",
                "Description": f"Oracle Cloud Compute Instance Configuration {configName} in Compartment {compartmentId} in {ociRegionName} does define that instances are encrypted with a Customer-managed Master Encryption Key (MEK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Cloud Compute instance should use a Customer-managed MEK refer to the Block Volume Encryption section of the Oracle Cloud Infrastructure Documentation for Compute.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/overview.htm#BlockVolumeEncryption"
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

## END ??