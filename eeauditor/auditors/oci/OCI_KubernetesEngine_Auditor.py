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

# Supported K8s Versions - https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengaboutk8sversions.htm#supportedk8sversions
OCI_SUPPORTED_K8S_VERSIONS = [
    "v1.26.2", "v1.25.4", "v1.24.1", "v1.23.4"
]

# Unsupported K8s Versions
OCI_DEPRECATED_K8S_VERSIONS = [
    "v1.22.5", "v1.21.5", "v1.20.11", "v1.20.8", "v1.19.15", "v1.19.12", "v1.19.7", "v1.18.10", "v1.17.13", "v1.17.9", "v1.16.15", "v1.15.12", "v1.15.7", "v1.14.8", "v1.13.x", "v1.12.7", "v1.12.6", "v1.11.9", "v1.11.8", "v1.11.x", "v1.10.x", "v1.9.x", "v1.8.x"
]

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

def get_oke_clusters(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oke_clusters")
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

    okeClient = oci.container_engine.ContainerEngineClient(config)

    aListOfClusters = []

    for compartment in ociCompartments:
        for cluster in okeClient.list_clusters(compartment_id=compartment).data:
            aListOfClusters.append(process_response(cluster))

    cache["get_oke_clusters"] = aListOfClusters
    return cache["get_oke_clusters"]

@registry.register_check("oci.oke")
def oci_oke_cluster_public_api_endpoint_check_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.OKE.1] Oracle Container Engine for Kubernetes (OKE) cluster API servers should not be accessible from the internet
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for cluster in get_oke_clusters(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["id"]
        clusterName = cluster["name"]
        compartmentId = cluster["compartment_id"]
        vcnId = cluster["vcn_id"]
        lifecycleState = cluster["lifecycle_state"]

        if cluster["endpoint_config"]["is_public_ip_enabled"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-oke-cluster-public-api-endpoint-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-oke-cluster-public-api-endpoint-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.OKE.1] Oracle Container Engine for Kubernetes (OKE) cluster API servers should not be accessible from the internet",
                "Description": f"Oracle Container Engine for Kubernetes cluster {clusterName} in Compartment {compartmentId} in {ociRegionName} does have an API server that is accessible from the internet. While Kubernetes API endpoints are further protected by network and identity security boundaries such as VCN Security Lists, Network Security Groups (NSGs), and Kubernetes RBAC - it is still possible to misconfigure these protections and expose your Kubernetes cluster to destruction or takeover from the internet. Oracle recommends that if you only want to expose workloads internally to your VCN and not to the internet, you create VCN-native clusters, with the Kubernetes API endpoint in a private subnet. Such clusters are sometimes referred to as private clusters. If you do not use private clusters, the cluster's Kubernetes API endpoint has a public IPv4 address and all traffic to the API (including traffic from the cluster's node pools) goes over the public network space. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on security best practices for access to your OKE clusters refer to the Security Best Practices section of the Oracle Cloud Infrastructure Documentation for Container Engine.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengbestpractices_topic-Security-best-practices.htm#contengbestpractices_topic-Security-best-practices",
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
                    "AssetService": "Oracle Container Engine for Kubernetes",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "OciOkeCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": clusterName,
                                "Id": clusterId,
                                "VcnId": vcnId,
                                "LifecycleState": lifecycleState
                            }
                        },
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-oke-cluster-public-api-endpoint-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-oke-cluster-public-api-endpoint-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.OKE.1] Oracle Container Engine for Kubernetes (OKE) cluster API servers should not be accessible from the internet",
                "Description": f"Oracle Container Engine for Kubernetes cluster {clusterName} in Compartment {compartmentId} in {ociRegionName} does not have an API server that is accessible from the internet.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on security best practices for access to your OKE clusters refer to the Security Best Practices section of the Oracle Cloud Infrastructure Documentation for Container Engine.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengbestpractices_topic-Security-best-practices.htm#contengbestpractices_topic-Security-best-practices",
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
                    "AssetService": "Oracle Container Engine for Kubernetes",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "OciOkeCluster",
                        "Id": clusterId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": clusterName,
                                "Id": clusterId,
                                "VcnId": vcnId,
                                "LifecycleState": lifecycleState
                            }
                        },
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

# [OCI.OKE.2] Oracle Container Engine for Kubernetes (OKE) cluster should have at least one Network Security Group (NSG) assigned - if not cluster["endpoint_config"]["nsg_ids"]
# Control access to the cluster's Kubernetes API endpoint using security rules defined for one or more network security groups (NSGs) that you specify. You can use security rules defined for NSGs instead of, or as well as, those defined for security lists.
# https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengcreatingclusterusingoke_topic-Using_the_Console_to_create_a_Custom_Cluster_with_Explicitly_Defined_Settings.htm

# [OCI.OKE.3] Oracle Container Engine for Kubernetes (OKE) clusters should enable image verification policies - cluster["image_policy_config"]["is_policy_enabled"] is false
# https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengenforcingsignedimagesfromocir.htm#Enforcing_Use_of_Signed_Images_from_Registry

# [OCI.OKE.4] Oracle Container Engine for Kubernetes (OKE) clusters with the Kubernetes dashboard enabled should be reviewed - cluster["options"]["add_ons"]["is_kubernetes_dashboard_enabled"] is True

# [OCI.OKE.5] Oracle Container Engine for Kubernetes (OKE) clusters should use the latest supported Kubernetes versions - if cluster["kubernetes_version"] not in OCI_SUPPORTED_K8S_VERSIONS
# Release Calendar: https://docs.oracle.com/en-us/iaas/Content/ContEng/Concepts/contengaboutk8sversions.htm#supportedk8sversions

# [OCI.OKE.6] Oracle Container Engine for Kubernetes (OKE) clusters should not use deprecated versions of Kubernetes - if cluster["kubernetes_version"] in OCI_DEPRECATED_K8S_VERSIONS




# **NODES**

# [OCI.OKE.7] Oracle Container Engine for Kubernetes (OKE) node pools should enable block volume in-transit encryption - if nodepool["node_config_details"]["is_pv_encryption_in_transit_enabled"] is not True

# [OCI.OKE.8] Oracle Container Engine for Kubernetes (OKE) node pools should have at least one Network Security Group (NSG) assigned - if not nodepool["node_config_details"]["nsg_ids"]

# [OCI.OKE.9] Oracle Container Engine for Kubernetes (OKE) node pools should protect pods with a Network Security Group (NSG) - if nodepool["node_config_details"]["node_pool_pod_network_option_details"]["pod_nsg_ids"] is None

# [OCI.OKE.10] Oracle Container Engine for Kubernetes (OKE) node pools should be configured to force terminate evicted worker nodes after the draining grace period - if nodepool["node_eviction_node_pool_settings"]["is_force_delete_after_grace_duration"] is False
# https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengdeletingworkernodes.htm#contengscalingnodepools_topic-Notes_on_cordon_and_drain

# [OCI.OKE.11] Oracle Container Engine for Kubernetes (OKE) node pools should use the latest supported Kubernetes versions - if nodepool["kubernetes_version"] not in OCI_SUPPORTED_K8S_VERSIONS

# [OCI.OKE.12] Oracle Container Engine for Kubernetes (OKE) node pools should not use deprecated versions of Kubernetes - if nodepool["kubernetes_version"] in OCI_DEPRECATED_K8S_VERSIONS

## END ??