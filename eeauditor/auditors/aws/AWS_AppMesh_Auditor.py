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

import datetime
from check_register import CheckRegister

registry = CheckRegister()

def list_meshes(cache, session):
    appmesh = session.client("appmesh")
    response = cache.get("list_meshes")
    if response:
        return response
    cache["list_meshes"] = appmesh.list_meshes()
    return cache["list_meshes"]


@registry.register_check("appmesh")
def appmesh_mesh_egress_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppMesh.1] App Mesh meshes should have the egress filter configured to DROP_ALL"""
    appmesh = session.client("appmesh")
    mesh = list_meshes(cache, session)
    myMesh = mesh["meshes"]
    for meshes in myMesh:
        meshName = str(meshes["meshName"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            response = appmesh.describe_mesh(meshName=meshName)
            meshArn = str(response["mesh"]["metadata"]["arn"])
            egressSpecCheck = str(response["mesh"]["spec"]["egressFilter"]["type"])
            if egressSpecCheck != "DROP_ALL":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": meshArn + "/appmesh-mesh-egress-filter-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": meshArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[AppMesh.1] App Mesh meshes should have the egress filter configured to DROP_ALL",
                    "Description": "App Mesh mesh "
                    + meshName
                    + " egress filter is not configured to DROP_ALL. Configuring the filter to DROP_ALL only allows egress to other resources in the mesh and to AWS SPNs for API Calls. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on egress filters refer to the EgressFilter Data Type section of the AWS App Mesh API Reference",
                            "Url": "https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_EgressFilter.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Networking",
                        "AssetService": "AWS App Mesh",
                        "AssetType": "Mesh"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppMeshMesh",
                            "Id": meshArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"MeshName": meshName}},
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": meshArn + "/appmesh-mesh-egress-filter-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": meshArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AppMesh.1] App Mesh meshes should have the egress filter configured to DROP_ALL",
                    "Description": "App Mesh mesh "
                    + meshName
                    + " egress filter is configured to DROP_ALL.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on egress filters refer to the EgressFilter Data Type section of the AWS App Mesh API Reference",
                            "Url": "https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_EgressFilter.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Networking",
                        "AssetService": "AWS App Mesh",
                        "AssetType": "Mesh"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAppMeshMesh",
                            "Id": meshArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"MeshName": meshName}},
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
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("appmesh")
def appmesh_virt_node_backed_default_tls_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppMesh.2] App Mesh virtual nodes should enforce TLS by default for all backends"""
    appmesh = session.client("appmesh")
    mesh = list_meshes(cache, session)
    myMesh = mesh["meshes"]
    for meshes in myMesh:
        meshName = str(meshes["meshName"])
        try:
            response = appmesh.list_virtual_nodes(meshName=meshName)
            for nodes in response["virtualNodes"]:
                nodeName = str(nodes["virtualNodeName"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    response = appmesh.describe_virtual_node(
                        meshName=meshName, virtualNodeName=nodeName
                    )
                    nodeArn = str(response["virtualNode"]["metadata"]["arn"])
                    backendDefaultsCheck = str(
                        response["virtualNode"]["spec"]["backendDefaults"]["clientPolicy"]
                    )
                    if backendDefaultsCheck == "{}":
                        # this is a type of failing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": nodeArn + "/appmesh-virtual-node-default-tls-policy-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": nodeArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[AppMesh.2] App Mesh virtual nodes should enforce TLS by default for all backends",
                            "Description": "App Mesh virtual node "
                            + nodeName
                            + " for the mesh "
                            + meshName
                            + " does not have a backend default client policy configured. Refer to the remediation instructions if this configuration is not intended",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on configuring TLS for virtual nodes refer to the Transport Layer Security (TLS) section of the AWS App Mesh User Guide",
                                    "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual-node-tls.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS App Mesh",
                                "AssetType": "Virtual Node"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsAppMeshVirtualNode",
                                    "Id": nodeArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "MeshName": meshName,
                                            "VirtualNodeName": nodeName,
                                        }
                                    },
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
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        backendTlsEnforceCheck = str(
                            response["virtualNode"]["spec"]["backendDefaults"]["clientPolicy"][
                                "tls"
                            ]["enforce"]
                        )
                        if backendTlsEnforceCheck == "False":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": nodeArn + "/appmesh-virtual-node-default-tls-policy-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "HIGH"},
                                "Confidence": 99,
                                "Title": "[AppMesh.2] App Mesh virtual nodes should enforce TLS by default for all backends",
                                "Description": "App Mesh virtual node "
                                + nodeName
                                + " for the mesh "
                                + meshName
                                + " does not enforce TLS in the default client policy. TLS will encrypt the traffic in between the Envoy virtual nodes in your mesh to offload the responsibility from your application code and will also terminate TLS for you. Refer to the remediation instructions if this configuration is not intended",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on configuring TLS for virtual nodes refer to the Transport Layer Security (TLS) section of the AWS App Mesh User Guide",
                                        "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual-node-tls.html",
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "AWS App Mesh",
                                    "AssetType": "Virtual Node"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsAppMeshVirtualNode",
                                        "Id": nodeArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "MeshName": meshName,
                                                "VirtualNodeName": nodeName,
                                            }
                                        },
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
                                    ],
                                },
                                "Workflow": {"Status": "NEW"},
                                "RecordState": "ACTIVE",
                            }
                            yield finding
                        else:
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": nodeArn + "/appmesh-virtual-node-default-tls-policy-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": "[AppMesh.2] App Mesh virtual nodes should enforce TLS by default for all backends",
                                "Description": "App Mesh virtual node "
                                + nodeName
                                + " for the mesh "
                                + meshName
                                + " enforces TLS in the default client policy.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on configuring TLS for virtual nodes refer to the Transport Layer Security (TLS) section of the AWS App Mesh User Guide",
                                        "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual-node-tls.html",
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "AWS App Mesh",
                                    "AssetType": "Virtual Node"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsAppMeshVirtualNode",
                                        "Id": nodeArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "MeshName": meshName,
                                                "VirtualNodeName": nodeName,
                                            }
                                        },
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
                                    ],
                                },
                                "Workflow": {"Status": "RESOLVED"},
                                "RecordState": "ARCHIVED",
                            }
                            yield finding
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)

@registry.register_check("appmesh")
def appmesh_virt_node_listener_strict_tls_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppMesh.3] App Mesh virtual node listeners should only accept connections with TLS enabled"""
    appmesh = session.client("appmesh")
    mesh = list_meshes(cache, session)
    myMesh = mesh["meshes"]
    for meshes in myMesh:
        meshName = str(meshes["meshName"])
        try:
            response = appmesh.list_virtual_nodes(meshName=meshName)
            for nodes in response["virtualNodes"]:
                nodeName = str(nodes["virtualNodeName"])
                try:
                    response = appmesh.describe_virtual_node(
                        meshName=meshName, virtualNodeName=nodeName
                    )
                    nodeArn = str(response["virtualNode"]["metadata"]["arn"])
                    for listeners in response["virtualNode"]["spec"]["listeners"]:
                        tlsStrictCheck = str(listeners["tls"]["mode"])
                        iso8601Time = (
                            datetime.datetime.utcnow()
                            .replace(tzinfo=datetime.timezone.utc)
                            .isoformat()
                        )
                        if tlsStrictCheck != "STRICT":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": nodeArn
                                + "/appmesh-virtual-node-listener-strict-tls-mode-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "HIGH"},
                                "Confidence": 99,
                                "Title": "[AppMesh.3] App Mesh virtual node listeners should only accept connections with TLS enabled",
                                "Description": "App Mesh virtual node "
                                + nodeName
                                + " for the mesh "
                                + meshName
                                + " does not enforce STRICT mode for listeners. Not setting a STRICT listener mode will accept non-encrypted connections to the listeners in the node. Refer to the remediation instructions if this configuration is not intended",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on configuring TLS for virtual nodes refer to the Transport Layer Security (TLS) section of the AWS App Mesh User Guide",
                                        "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual-node-tls.html",
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "AWS App Mesh",
                                    "AssetType": "Virtual Node"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsAppMeshVirtualNode",
                                        "Id": nodeArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "MeshName": meshName,
                                                "VirtualNodeName": nodeName,
                                            }
                                        },
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
                                    ],
                                },
                                "Workflow": {"Status": "NEW"},
                                "RecordState": "ACTIVE",
                            }
                            yield finding
                        else:
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": nodeArn
                                + "/appmesh-virtual-node-listener-strict-tls-mode-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure"
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": "[AppMesh.3] App Mesh virtual node listeners should only accept connections with TLS enabled",
                                "Description": "App Mesh virtual node "
                                + nodeName
                                + " for the mesh "
                                + meshName
                                + " enforces STRICT mode for listeners.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on configuring TLS for virtual nodes refer to the Transport Layer Security (TLS) section of the AWS App Mesh User Guide",
                                        "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual-node-tls.html",
                                    }
                                },
                                "ProductFields": {
                                    "ProductName": "ElectricEye",
                                    "Provider": "AWS",
                                    "AssetClass": "Networking",
                                    "AssetService": "AWS App Mesh",
                                    "AssetType": "Virtual Node"
                                },
                                "Resources": [
                                    {
                                        "Type": "AwsAppMeshVirtualNode",
                                        "Id": nodeArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "MeshName": meshName,
                                                "VirtualNodeName": nodeName,
                                            }
                                        },
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
                                    ],
                                },
                                "Workflow": {"Status": "RESOLVED"},
                                "RecordState": "ARCHIVED",
                            }
                            yield finding
                except Exception as e:
                    if str(e) == "'tls'":
                        pass
                    else:
                        print(e)
        except Exception as e:
            print(e)

@registry.register_check("appmesh")
def appmesh_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AppMesh.4] App Mesh virtual nodes should define an HTTP access log path to enable log exports for Envoy proxies"""
    appmesh = session.client("appmesh")
    mesh = list_meshes(cache, session)
    myMesh = mesh["meshes"]
    for meshes in myMesh:
        meshName = str(meshes["meshName"])
        try:
            response = appmesh.list_virtual_nodes(meshName=meshName)
            for nodes in response["virtualNodes"]:
                nodeName = str(nodes["virtualNodeName"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                try:
                    response = appmesh.describe_virtual_node(
                        meshName=meshName, virtualNodeName=nodeName
                    )
                    nodeArn = str(response["virtualNode"]["metadata"]["arn"])
                    loggingCheck = str(response["virtualNode"]["spec"]["logging"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": nodeArn + "/appmesh-virtual-node-access-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": nodeArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[AppMesh.4] App Mesh virtual nodes should define an HTTP access log path to enable log exports for Envoy proxies",
                        "Description": "App Mesh virtual node "
                        + nodeName
                        + " for the mesh "
                        + meshName
                        + " specifies a path for HTTP access logs.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on configuring access logging for virtual nodes refer to the Creating a Virtual Node section of the AWS App Mesh User Guide",
                                "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual_nodes.html#vn-create-virtual-node",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "AssetClass": "Networking",
                            "AssetService": "AWS App Mesh",
                            "AssetType": "Virtual Node"
                        },
                        "Resources": [
                            {
                                "Type": "AwsAppMeshVirtualNode",
                                "Id": nodeArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "MeshName": meshName,
                                        "VirtualNodeName": nodeName,
                                        "AccessLogPath": loggingCheck,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 DE.AE-3",
                                "NIST SP 800-53 Rev. 4 AU-6",
                                "NIST SP 800-53 Rev. 4 CA-7",
                                "NIST SP 800-53 Rev. 4 IR-4",
                                "NIST SP 800-53 Rev. 4 IR-5",
                                "NIST SP 800-53 Rev. 4 IR-8",
                                "NIST SP 800-53 Rev. 4 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.7",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                except Exception as e:
                    if str(e) == "'logging'":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": nodeArn + "/appmesh-virtual-node-access-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": nodeArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[AppMesh.4] App Mesh virtual nodes should define an HTTP access log path to enable log exports for Envoy proxies",
                            "Description": "App Mesh virtual node "
                            + nodeName
                            + " for the mesh "
                            + meshName
                            + " does not specify a path for HTTP access logs. Specifying a path will allow you to use Docker log drivers or otherwise to pipe logs out of Envoy to another service such as CloudWatch. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on configuring access logging for virtual nodes refer to the Creating a Virtual Node section of the AWS App Mesh User Guide",
                                    "Url": "https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual_nodes.html#vn-create-virtual-node",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Networking",
                                "AssetService": "AWS App Mesh",
                                "AssetType": "Virtual Node"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsAppMeshVirtualNode",
                                    "Id": nodeArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "MeshName": meshName,
                                            "VirtualNodeName": nodeName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-3",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 IR-5",
                                    "NIST SP 800-53 Rev. 4 IR-8",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.12.4.1",
                                    "ISO 27001:2013 A.16.1.7",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        print(e)
        except Exception as e:
            print(e)