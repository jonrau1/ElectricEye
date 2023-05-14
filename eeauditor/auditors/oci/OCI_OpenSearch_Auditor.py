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

def get_oci_opensearch_clusters(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_oci_opensearch_clusters")
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

    opensearchClient = oci.opensearch.OpensearchClusterClient(config)

    aListOfClusters = []

    for compartment in ociCompartments:
        clusters = opensearchClient.list_opensearch_clusters(compartment_id=compartment).data
        for cluster in process_response(clusters)["items"]:
            getCluster = process_response(opensearchClient.get_opensearch_cluster(opensearch_cluster_id=cluster["id"]).data)
            aListOfClusters.append(
                process_response(
                    getCluster
                )
            )

    cache["get_oci_opensearch_clusters"] = aListOfClusters
    return cache["get_oci_opensearch_clusters"]

@registry.register_check("oci.opensearch")
def oci_open_search_cluster_security_mode_enforced_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.OpenSearch.1] Oracle Search with OpenSearch clusters should have Security Mode enabled and set to Enforcing
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for cluster in get_oci_opensearch_clusters(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["id"]
        clusterName = cluster["display_name"]
        compartmentId = cluster["compartment_id"]
        vcnId = cluster["vcn_id"]
        lifecycleState = cluster["lifecycle_state"]

        if cluster["security_mode"] != "ENFORCING":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-opensearch-cluster-security-mode-enforcing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-opensearch-cluster-security-mode-enforcing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.OpenSearch.1] OpenSearch clusters should have Security Mode enabled and set to Enforcing",
                "Description": f"Oracle Search with OpenSearch cluster {clusterName} in Compartment {compartmentId} in {ociRegionName} does not have Security Mode enabled and set to Enforcing. OCI Search with OpenSearch includes the OpenSearch security plugin to enable role-based access to your OpenSearch clusters. With role-based access control, you can define and control what users can access and configure when connecting to an OpenSearch cluster. Role-based access control requires that you specify a username and password when connecting to a cluster or when accessing the cluster's OpenSearch Dashboard. Enforcing mode requires a username and password anytime you connect to a cluster or the cluster's OpenSearch Dashboard. This is the recommended mode when upgrading an older cluster and is the only mode supported for new clusters. You must enable the modes sequentially. Enable permissive mode first before you enable enforcing mode. You can then change the security mode for your cluster to enforcing, but you can also choose to keep the security mode set to permissive. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Search with OpenSearch cluster requires enforced RBAC refer to the Upgrading an Existing Cluster for Role-Based Access Control section of the Oracle Cloud Infrastructure Documentation for Search with OpenSearch.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/search-opensearch/Tasks/updatingclustersecuritymode.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Search with OpenSearch",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "OciOpenSearchCluster",
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
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-opensearch-cluster-security-mode-enforcing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{clusterId}/oci-opensearch-cluster-security-mode-enforcing-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.OpenSearch.1] OpenSearch clusters should have Security Mode enabled and set to Enforcing",
                "Description": f"Oracle Search with OpenSearch cluster {clusterName} in Compartment {compartmentId} in {ociRegionName} does have Security Mode enabled and set to Enforcing.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Oracle Search with OpenSearch cluster requires enforced RBAC refer to the Upgrading an Existing Cluster for Role-Based Access Control section of the Oracle Cloud Infrastructure Documentation for Search with OpenSearch.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/search-opensearch/Tasks/updatingclustersecuritymode.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle Search with OpenSearch",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "OciOpenSearchCluster",
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
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??