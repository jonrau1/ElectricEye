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

def get_container_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_container_instances")
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

    ciClient = oci.container_instances.ContainerInstanceClient(config)

    containerInstancesAreListedHere = []

    for compartment in ociCompartments:
        for cinstance in process_response(ciClient.list_container_instances(compartment_id=compartment).data)["items"]:
            containerInstancesAreListedHere.append(
                process_response(
                    ciClient.get_container_instance(container_instance_id=cinstance["id"]).data
                )
            )

    cache["get_container_instances"] = containerInstancesAreListedHere
    return cache["get_container_instances"]

@registry.register_check("oci.containerinstances")
def oci_container_instance_container_restart_policy_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ContainerInstance.1] Oracle Container Instances should consider defining a container restart policy
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for containerinstance in get_container_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(containerinstance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = containerinstance["compartment_id"]
        containerinstanceId = containerinstance["id"]
        containerinstanceName = containerinstance["display_name"]
        lifecycleState = containerinstance["lifecycle_state"]
        createdAt = str(containerinstance["time_created"])

        if containerinstance["container_restart_policy"] == "NEVER":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-container-restart-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-container-restart-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ContainerInstance.1] Oracle Container Instances should consider defining a container restart policy",
                "Description": f"Oracle Container Instance {containerinstanceName} in Compartment {compartmentId} in {ociRegionName} does not define a container restart policy. You can set the restart policy for the containers on a container instance when you create them. When an individual container exits (stops, restarts, or fails), the exit code and exit time is available in the API and the restart policy is applied. If all containers exit and do not restart, the container instance is shut down. The following options are available: Always: Containers always restart, even if they exit successfully. 'Always' is preferred if you want to make sure your container is always running (example: a web server), Never: Containers never restart, regardless of why they exited, and On failure: Containers only restart if they exit with an error 'On failure' is preferred if you want to accomplish a certain task and ensure that it completes successfully. Evaluate the type of workloads running on your Container Instance before commiting to a specific restart policy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Container Restart Policies refer to the Creating a Container Instance section of the Oracle Cloud Infrastructure Documentation for Container Instances.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/container-instances/creating-a-container-instance.htm#console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Oracle Container Instance Serivce",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciContainerInstanceInstance",
                        "Id": containerinstanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": containerinstanceName,
                                "Id": containerinstanceId,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-container-restart-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-container-restart-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ContainerInstance.1] Oracle Container Instances should consider defining a container restart policy",
                "Description": f"Oracle Container Instance {containerinstanceName} in Compartment {compartmentId} in {ociRegionName} does define a container restart policy.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Container Restart Policies refer to the Creating a Container Instance section of the Oracle Cloud Infrastructure Documentation for Container Instances.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/container-instances/creating-a-container-instance.htm#console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Oracle Container Instance Serivce",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciContainerInstanceInstance",
                        "Id": containerinstanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": containerinstanceName,
                                "Id": containerinstanceId,
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

@registry.register_check("oci.containerinstances")
def oci_container_instance_graceful_shutdown_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ContainerInstance.2] Oracle Container Instances should consider defining a graceful shutdown timeout
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for containerinstance in get_container_instances(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(containerinstance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = containerinstance["compartment_id"]
        containerinstanceId = containerinstance["id"]
        containerinstanceName = containerinstance["display_name"]
        lifecycleState = containerinstance["lifecycle_state"]
        createdAt = str(containerinstance["time_created"])

        if containerinstance["graceful_shutdown_timeout_in_seconds"] == 0 or "0":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-graceful-shutdown-timeout-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-graceful-shutdown-timeout-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ContainerInstance.2] Oracle Container Instances should consider defining a graceful shutdown timeout",
                "Description": f"Oracle Container Instance {containerinstanceName} in Compartment {compartmentId} in {ociRegionName} does not define a graceful shutdown timeout. The Graceful Shutdown Timeout allows you to specify the maximum amount of time (in seconds) that your container instance will be given to shut down gracefully after it receives a SIGTERM signal, which is intended to give the process an opportunity to perform any necessary cleanup or shutdown procedures before it is forcibly terminated. Consider setting a longer time if you need to wait for the container to gracefully shutdown, if not, keep the default at 0 which will kill the containers as fast as the Container Instance can, sweet murderous rage against containers is good for some workloads I suppose. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Container Restart Policies refer to the Creating a Container Instance section of the Oracle Cloud Infrastructure Documentation for Container Instances.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/container-instances/creating-a-container-instance.htm#console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Oracle Container Instance Serivce",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciContainerInstanceInstance",
                        "Id": containerinstanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": containerinstanceName,
                                "Id": containerinstanceId,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-graceful-shutdown-timeout-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{containerinstanceId}/oci-container-instance-graceful-shutdown-timeout-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ContainerInstance.2] Oracle Container Instances should consider defining a graceful shutdown timeout",
                "Description": f"Oracle Container Instance {containerinstanceName} in Compartment {compartmentId} in {ociRegionName} does define a graceful shutdown timeout.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Container Restart Policies refer to the Creating a Container Instance section of the Oracle Cloud Infrastructure Documentation for Container Instances.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/container-instances/creating-a-container-instance.htm#console",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Oracle Container Instance Serivce",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "OciContainerInstanceInstance",
                        "Id": containerinstanceId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": containerinstanceName,
                                "Id": containerinstanceId,
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

## END ??