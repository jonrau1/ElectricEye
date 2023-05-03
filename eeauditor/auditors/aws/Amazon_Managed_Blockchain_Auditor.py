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
import base64
import json

registry = CheckRegister()

def list_networks(cache, session):
    amb = session.client("managedblockchain")
    response = cache.get("list_networks")
    if response:
        return response
    cache["list_networks"] = amb.list_networks(Framework="HYPERLEDGER_FABRIC")
    return cache["list_networks"]

@registry.register_check("managedblockchain")
def amb_fabric_node_chaincode_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AMB.Fabric.1] Amazon Managed Blockchain Fabric peer nodes should have chaincode logging enabled"""
    amb = session.client("managedblockchain")
    response = list_networks(cache, session)
    myFabricNetworks = response["Networks"]
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks["Id"])
        response = amb.list_members(
            NetworkId=fabricNetworkId, Status="AVAILABLE", IsOwned=True
        )
        for members in response["Members"]:
            memberId = str(members["Id"])
            response = amb.list_nodes(
                NetworkId=fabricNetworkId, MemberId=memberId, Status="AVAILABLE",
            )
            for nodes in response["Nodes"]:
                peerNodeId = str(nodes["Id"])
                response = amb.get_node(
                    NetworkId=fabricNetworkId, MemberId=memberId, NodeId=peerNodeId,
                )
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(response,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                nodeArn = f"arn:{awsPartition}:managedblockchain:{awsRegion}:{awsAccountId}:nodes/{peerNodeId}"
                chaincodeLogCheck = str(
                    response["Node"]["LogPublishingConfiguration"]["Fabric"][
                        "ChaincodeLogs"
                    ]["Cloudwatch"]["Enabled"]
                )
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                if chaincodeLogCheck == "False":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": nodeArn
                        + "/managedblockchain-fabric-node-chaincode-logs-check",
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
                        "Title": "[AMB.Fabric.1] Amazon Managed Blockchain Fabric peer nodes should have chaincode logging enabled",
                        "Description": "Amazon Managed Blockchain Fabric peer node "
                        + peerNodeId
                        + " does not have chaincode logging enabled. Chaincode logs help you analyze and debug the business logic and execution of chaincode on a peer node. They contain the results of instantiating, invoking, and querying the chaincode. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                                "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Blockchain",
                            "AssetService": "Amazon Managed Blockchain",
                            "AssetComponent": "Peer Node"
                        },
                        "Resources": [
                            {
                                "Type": "AwsManagedBlockchainPeerNode",
                                "Id": nodeArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "NetworkId": fabricNetworkId,
                                        "MemberId": memberId,
                                        "NodeId": peerNodeId,
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
                                "ISO 27001:2013 A.16.1.7"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": nodeArn
                        + "/managedblockchain-fabric-node-chaincode-logs-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                        "Title": "[AMB.Fabric.1] Amazon Managed Blockchain Fabric peer nodes should have chaincode logging enabled",
                        "Description": "Amazon Managed Blockchain Fabric peer node "
                        + peerNodeId
                        + " has chaincode logging enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                                "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Blockchain",
                            "AssetService": "Amazon Managed Blockchain",
                            "AssetComponent": "Peer Node"
                        },
                        "Resources": [
                            {
                                "Type": "AwsManagedBlockchainPeerNode",
                                "Id": nodeArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "NetworkId": fabricNetworkId,
                                        "MemberId": memberId,
                                        "NodeId": peerNodeId,
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

@registry.register_check("managedblockchain")
def amb_fabric_node_peernode_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AMB.Fabric.2] Amazon Managed Blockchain Fabric peer nodes should have peer node logging enabled"""
    amb = session.client("managedblockchain")
    response = list_networks(cache, session)
    myFabricNetworks = response["Networks"]
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks["Id"])
        response = amb.list_members(
            NetworkId=fabricNetworkId, Status="AVAILABLE", IsOwned=True
        )
        for members in response["Members"]:
            memberId = str(members["Id"])
            response = amb.list_nodes(
                NetworkId=fabricNetworkId, MemberId=memberId, Status="AVAILABLE",
            )
            for nodes in response["Nodes"]:
                peerNodeId = str(nodes["Id"])
                response = amb.get_node(
                    NetworkId=fabricNetworkId, MemberId=memberId, NodeId=peerNodeId,
                )
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(response,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                nodeArn = f"arn:{awsPartition}:managedblockchain:{awsRegion}:{awsAccountId}:nodes/{peerNodeId}"
                peerNodeLogCheck = str(
                    response["Node"]["LogPublishingConfiguration"]["Fabric"][
                        "PeerLogs"
                    ]["Cloudwatch"]["Enabled"]
                )
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                if peerNodeLogCheck == "False":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": nodeArn
                        + "/managedblockchain-fabric-node-peernode-logs-check",
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
                        "Title": "[AMB.Fabric.2] Amazon Managed Blockchain Fabric peer nodes should have peer node logging enabled",
                        "Description": "Amazon Managed Blockchain Fabric peer node "
                        + peerNodeId
                        + " does not have peer node logging enabled. Peer node logs help you debug timeout errors associated with proposals and identify rejected proposals that do not meet the endorsement policies. Peer node logs contain messages generated when your client submits transaction proposals to peer nodes, requests to join channels, enrolls an admin peer, and lists the chaincode instances on a peer node. Peer node logs also contain the results of chaincode installation. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                                "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Blockchain",
                            "AssetService": "Amazon Managed Blockchain",
                            "AssetComponent": "Peer Node"
                        },
                        "Resources": [
                            {
                                "Type": "AwsManagedBlockchainPeerNode",
                                "Id": nodeArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "NetworkId": fabricNetworkId,
                                        "MemberId": memberId,
                                        "NodeId": peerNodeId,
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
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": nodeArn
                        + "/managedblockchain-fabric-node-peernode-logs-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                        "Title": "[AMB.Fabric.2] Amazon Managed Blockchain Fabric peer nodes should have peer node logging enabled",
                        "Description": "Amazon Managed Blockchain Fabric peer node "
                        + peerNodeId
                        + " has peer node logging enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                                "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Blockchain",
                            "AssetService": "Amazon Managed Blockchain",
                            "AssetComponent": "Peer Node"
                        },
                        "Resources": [
                            {
                                "Type": "AwsManagedBlockchainPeerNode",
                                "Id": nodeArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "NetworkId": fabricNetworkId,
                                        "MemberId": memberId,
                                        "NodeId": peerNodeId,
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

@registry.register_check("managedblockchain")
def amb_fabric_member_ca_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AMB.Fabric.3] Amazon Managed Blockchain Fabric members should have certificate authority (CA) logging enabled"""
    amb = session.client("managedblockchain")
    response = list_networks(cache, session)
    myFabricNetworks = response["Networks"]
    for networks in myFabricNetworks:
        fabricNetworkId = str(networks["Id"])
        response = amb.list_members(
            NetworkId=fabricNetworkId, Status="AVAILABLE", IsOwned=True
        )
        for members in response["Members"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(members,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            memberId = str(members["Id"])
            response = amb.get_member(NetworkId=fabricNetworkId, MemberId=memberId)
            memberArn = f"arn:{awsPartition}:managedblockchain:{awsRegion}:{awsAccountId}:members/{memberId}"
            memberCaLogCheck = str(
                response["Member"]["LogPublishingConfiguration"]["Fabric"]["CaLogs"][
                    "Cloudwatch"
                ]["Enabled"]
            )
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            if memberCaLogCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": memberArn + "/managedblockchain-member-ca-logs-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": memberArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[AMB.Fabric.3] Amazon Managed Blockchain Fabric members should have certificate authority (CA) logging enabled",
                    "Description": "Amazon Managed Blockchain Fabric member "
                    + memberId
                    + " does not have certificate authority (CA) logging enabled. CA logs help you determine when a member in your account joins the network, or when new peers register with a member CA. You can use CA logs to debug problems related to certificates and enrollment. CA logging can be enabled and disabled for each member. A single log stream for the CA exists for each member. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                            "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Managed Blockchain",
                        "AssetComponent": "Member"
                    },
                    "Resources": [
                        {
                            "Type": "AwsManagedBlockchainMember",
                            "Id": memberArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "NetworkId": fabricNetworkId,
                                    "MemberId": memberId,
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
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": memberArn + "/managedblockchain-member-ca-logs-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": memberArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AMB.Fabric.3] Amazon Managed Blockchain Fabric members should have certificate authority (CA) logging enabled",
                    "Description": "Amazon Managed Blockchain Fabric member "
                    + memberId
                    + " has certificate authority (CA) logging enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on logging and monitoring Amazon Managed Blockchain refer to the Enabling and Disabling Logs section of the Amazon Managed Blockchain Management Guide",
                            "Url": "https://docs.aws.amazon.com/managed-blockchain/latest/managementguide/monitoring-cloudwatch-logs.html#monitoring-enable",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Managed Blockchain",
                        "AssetComponent": "Member"
                    },
                    "Resources": [
                        {
                            "Type": "AwsManagedBlockchainMember",
                            "Id": memberArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "NetworkId": fabricNetworkId,
                                    "MemberId": memberId,
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