# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
appmesh = boto3.client("appmesh")
# loop through AWS App Mesh meshes


def list_meshes(cache):
    response = cache.get("list_meshes")
    if response:
        return response
    cache["list_meshes"] = appmesh.list_meshes()
    return cache["list_meshes"]


@registry.register_check("appmesh")
def appmesh_mesh_egress_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    mesh = list_meshes(cache=cache)
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
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": meshArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"meshName": meshName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-3",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-17",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-20",
                            "NIST SP 800-53 SC-15",
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
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
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
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": meshArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"meshName": meshName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-3",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-17",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-20",
                            "NIST SP 800-53 SC-15",
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
def appmesh_virt_node_backed_default_tls_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    mesh = list_meshes(cache=cache)
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
                            "GeneratorId": nodeArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
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
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": nodeArn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "meshName": meshName,
                                            "virtualNodeName": nodeName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.DS-2",
                                    "NIST SP 800-53 SC-8",
                                    "NIST SP 800-53 SC-11",
                                    "NIST SP 800-53 SC-12",
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
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
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
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "Other",
                                        "Id": nodeArn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "meshName": meshName,
                                                "virtualNodeName": nodeName,
                                            }
                                        },
                                    }
                                ],
                                "Compliance": {
                                    "Status": "FAILED",
                                    "RelatedRequirements": [
                                        "NIST CSF PR.DS-2",
                                        "NIST SP 800-53 SC-8",
                                        "NIST SP 800-53 SC-11",
                                        "NIST SP 800-53 SC-12",
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
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
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
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "Other",
                                        "Id": nodeArn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "meshName": meshName,
                                                "virtualNodeName": nodeName,
                                            }
                                        },
                                    }
                                ],
                                "Compliance": {
                                    "Status": "PASSED",
                                    "RelatedRequirements": [
                                        "NIST CSF PR.DS-2",
                                        "NIST SP 800-53 SC-8",
                                        "NIST SP 800-53 SC-11",
                                        "NIST SP 800-53 SC-12",
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
def appmesh_virt_node_listener_strict_tls_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    mesh = list_meshes(cache=cache)
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
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
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
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "Other",
                                        "Id": nodeArn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "meshName": meshName,
                                                "virtualNodeName": nodeName,
                                            }
                                        },
                                    }
                                ],
                                "Compliance": {
                                    "Status": "FAILED",
                                    "RelatedRequirements": [
                                        "NIST CSF PR.DS-2",
                                        "NIST SP 800-53 SC-8",
                                        "NIST SP 800-53 SC-11",
                                        "NIST SP 800-53 SC-12",
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
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": nodeArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices"
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
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "Other",
                                        "Id": nodeArn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "Other": {
                                                "meshName": meshName,
                                                "virtualNodeName": nodeName,
                                            }
                                        },
                                    }
                                ],
                                "Compliance": {
                                    "Status": "PASSED",
                                    "RelatedRequirements": [
                                        "NIST CSF PR.DS-2",
                                        "NIST SP 800-53 SC-8",
                                        "NIST SP 800-53 SC-11",
                                        "NIST SP 800-53 SC-12",
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
def appmesh_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    mesh = list_meshes(cache=cache)
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
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "Other",
                                "Id": nodeArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "meshName": meshName,
                                        "virtualNodeName": nodeName,
                                        "accessLogPath": loggingCheck,
                                    }
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-3",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 IR-5",
                                "NIST SP 800-53 IR-8",
                                "NIST SP 800-53 SI-4",
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": nodeArn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "meshName": meshName,
                                            "virtualNodeName": nodeName,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF DE.AE-3",
                                    "NIST SP 800-53 AU-6",
                                    "NIST SP 800-53 CA-7",
                                    "NIST SP 800-53 IR-4",
                                    "NIST SP 800-53 IR-5",
                                    "NIST SP 800-53 IR-8",
                                    "NIST SP 800-53 SI-4",
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
