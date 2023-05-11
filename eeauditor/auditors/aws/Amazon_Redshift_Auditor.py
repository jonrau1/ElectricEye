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

def describe_redshift_clusters(cache, session):
    redshift = session.client("redshift")
    redshiftClusters = []
    response = cache.get("describe_redshift_clusters")
    if response:
        return response
    paginator = redshift.get_paginator('describe_clusters')
    if paginator:
        for page in paginator.paginate():
            for cluster in page["Clusters"]:
                redshiftClusters.append(cluster)
        cache["describe_redshift_clusters"] = redshiftClusters
        return cache["describe_redshift_clusters"]

@registry.register_check("redshift")
def redshift_cluster_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.1] Amazon Redshift clusters should not be publicly accessible"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["PubliclyAccessible"] == True:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Redshift.1] Amazon Redshift clusters should not be publicly accessible",
                "Description": f"Redshift cluster {clusterId} is configured to be publicly reachable. When public access is configured, your Redshift Cluster can accept connections from outside of your VPC on a discoverable IP which can lead to attacks against the availability or confidentiality of data within your Cluster. You should always use private connectivity into your Redshift clusters with the usage of Bastions, VPNs, and otherwise before making your Cluster public. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.1] Amazon Redshift clusters should not be publicly accessible",
                "Description": f"Redshift cluster {clusterId} is not publicly accessible.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
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

@registry.register_check("redshift")
def redshift_cluster_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.2] Amazon Redshift clusters should be encrypted at rest"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["Encrypted"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
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
                "Title": "[Redshift.2] Amazon Redshift clusters should be encrypted at rest",
                "Description": f"Redshift cluster {clusterId} is not encrypted at rest. In Amazon Redshift, you can enable database encryption for your clusters to help protect data at rest. When you enable encryption for a cluster, the data blocks and system metadata are encrypted for the cluster and its snapshots. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.2] Amazon Redshift clusters should be encrypted at rest",
                "Description": f"Redshift cluster {clusterId} is encrypted at rest.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
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

@registry.register_check("redshift")
def redshift_cluster_enhanced_vpc_routing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.3] Amazon Redshift clusters should utilize enhanced VPC routing"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["EnhancedVpcRouting"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-enhanced-vpc-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift.3] Amazon Redshift clusters should utilize enhanced VPC routing",
                "Description": f"Redshift cluster {clusterId} is not utilizing enhanced VPC routing. When you use Amazon Redshift enhanced VPC routing, Amazon Redshift forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service. By using enhanced VPC routing, you can use standard VPC features, such as VPC security groups, network access control lists (ACLs), VPC endpoints, VPC endpoint policies, internet gateways, and Domain Name System (DNS) servers, as described in the Amazon VPC User Guide. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-enhanced-vpc-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.3] Amazon Redshift clusters should utilize enhanced VPC routing",
                "Description": f"Redshift cluster {clusterId} is utilizing enhanced VPC routing.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift")
def redshift_cluster_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.4] Amazon Redshift clusters should have audit logging enabled"""
    redshift = session.client("redshift")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if redshift.describe_logging_status(ClusterIdentifier=clusterId)["LoggingEnabled"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift.4] Amazon Redshift clusters should have audit logging enabled",
                "Description": f"Redshift cluster {clusterId} does not have audit logging enabled. Amazon Redshift logs information about connections and user activities in your database. These logs help you to monitor the database for security and troubleshooting purposes, a process called database auditing. The logs are stored in Amazon S3 buckets. These provide convenient access with data-security features for users who are responsible for monitoring activities in the database. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift audit logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
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
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.4] Amazon Redshift clusters should have audit logging enabled",
                "Description": f"Redshift cluster {clusterId} has audit logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift")
def redshift_cluster_default_username_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.5] Amazon Redshift clusters should not use the default Admin username"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["MasterUsername"] == "awsuser":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-default-admin-username-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift.5] Amazon Redshift clusters should not use the default Admin username",
                "Description": f"Redshift cluster {clusterId} is using the default Redshift Admin/Master username of 'awsuser'. When creating a Redshift cluster, you should change the default admin username to a unique value. Default usernames are public knowledge and should be changed upon configuration. Changing the default usernames reduces the risk of unintended access. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot change the admin username for your Amazon Redshift cluster after it is created. To create a new cluster refer to the Getting started with Amazon Redshift section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/gsg/getting-started.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1078"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-default-admin-username-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.5] Amazon Redshift clusters should not use the default Admin username",
                "Description": f"Redshift cluster {clusterId} is not using the default Redshift Admin/Master username of 'awsuser'.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot change the admin username for your Amazon Redshift cluster after it is created. To create a new cluster refer to the Getting started with Amazon Redshift section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/gsg/getting-started.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1078"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift")
def redshift_cluster_user_activity_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.6] Amazon Redshift clusters should have user activity logging enabled"""
    redshift = session.client("redshift")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        # Parse Cluster Parameter Group for check data
        for param in redshift.describe_cluster_parameters(ParameterGroupName=clusterPgName)["Parameters"]:
            # ignore the parameters we don't want
            if param["ParameterName"] != "enable_user_activity_logging":
                continue
            else:
                if str(param["ParameterValue"]) == "false":
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/redshift-cluster-user-activity-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[Redshift.6] Amazon Redshift clusters should have user activity logging enabled",
                        "Description": f"Redshift cluster {clusterId} does not have user activity logging enabled. User activity logging Logs each query before it's run on the database, and is useful primarily for troubleshooting purposes. It tracks information about the types of queries that both the users and the system perform in the database. This requires Audit Logging to be enabled first. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Redshift audit logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                                "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Analytics",
                            "AssetService": "Amazon Redshift",
                            "AssetComponent": "Cluster"
                        },
                        "Resources": [
                            {
                                "Type": "AwsRedshiftCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsRedshiftCluster": {
                                        "AvailabilityZone": clusterAz,
                                        "ClusterIdentifier": clusterId,
                                        "ClusterParameterGroups": [
                                            {
                                                "ParameterGroupName": clusterPgName
                                            }
                                        ],
                                        "ClusterSubnetGroupName": clusterSubnetGroupName,
                                        "ClusterVersion": clusterVersion,
                                        "DBName": dbName,
                                        "Endpoint": {
                                            "Address": endpointAddr,
                                            "Port": endpointPort
                                        },
                                        "NodeType": nodeType,
                                        "VpcId": vpcId
                                    }
                                }
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
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/redshift-cluster-user-activity-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Redshift.6] Amazon Redshift clusters should have user activity logging enabled",
                        "Description": f"Redshift cluster {clusterId} does not have user activity logging enabled. User activity logging Logs each query before it's run on the database, and is useful primarily for troubleshooting purposes. It tracks information about the types of queries that both the users and the system perform in the database. This requires Audit Logging to be enabled first. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Redshift audit logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                                "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Analytics",
                            "AssetService": "Amazon Redshift",
                            "AssetComponent": "Cluster"
                        },
                        "Resources": [
                            {
                                "Type": "AwsRedshiftCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsRedshiftCluster": {
                                        "AvailabilityZone": clusterAz,
                                        "ClusterIdentifier": clusterId,
                                        "ClusterParameterGroups": [
                                            {
                                                "ParameterGroupName": clusterPgName
                                            }
                                        ],
                                        "ClusterSubnetGroupName": clusterSubnetGroupName,
                                        "ClusterVersion": clusterVersion,
                                        "DBName": dbName,
                                        "Endpoint": {
                                            "Address": endpointAddr,
                                            "Port": endpointPort
                                        },
                                        "NodeType": nodeType,
                                        "VpcId": vpcId
                                    }
                                }
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
                                "ISO 27001:2013 A.16.1.7"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding

@registry.register_check("redshift")
def redshift_cluster_ssl_connections_only_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.7] Amazon Redshift clusters should enforce encryption in transit"""
    redshift = session.client("redshift")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        # Parse Cluster Parameter Group for check data
        for param in redshift.describe_cluster_parameters(ParameterGroupName=clusterPgName)["Parameters"]:
            # ignore the parameters we don't want
            if param["ParameterName"] != "require_ssl":
                continue
            else:
                if str(param["ParameterValue"]) == "false":
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/redshift-ssl-connections-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[Redshift.7] Amazon Redshift clusters should enforce encryption in transit",
                        "Description": f"Redshift cluster {clusterId} does not enforce encryption in transit (SSL connectivity). TLS can be used to help prevent potential attackers from using person-in-the-middle or similar attacks to eavesdrop on or manipulate network traffic. Only encrypted connections over TLS should be allowed. Encrypting data in transit can affect performance. You should test your application with this feature to understand the performance profile and the impact of TLS. This check fails if the Amazon Redshift cluster parameter require_SSL is not set to 1. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Redshift SSL encryption in transit and how to configure it refer to the Encryption in transit section of the Amazon Redshift Cluster Management Guide",
                                "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/security-encryption-in-transit.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Analytics",
                            "AssetService": "Amazon Redshift",
                            "AssetComponent": "Cluster"
                        },
                        "Resources": [
                            {
                                "Type": "AwsRedshiftCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsRedshiftCluster": {
                                        "AvailabilityZone": clusterAz,
                                        "ClusterIdentifier": clusterId,
                                        "ClusterParameterGroups": [
                                            {
                                                "ParameterGroupName": clusterPgName
                                            }
                                        ],
                                        "ClusterSubnetGroupName": clusterSubnetGroupName,
                                        "ClusterVersion": clusterVersion,
                                        "DBName": dbName,
                                        "Endpoint": {
                                            "Address": endpointAddr,
                                            "Port": endpointPort
                                        },
                                        "NodeType": nodeType,
                                        "VpcId": vpcId
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
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/redshift-ssl-connections-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Redshift.7] Amazon Redshift clusters should enforce encryption in transit",
                        "Description": f"Redshift cluster {clusterId} enforces encryption in transit (SSL connectivity).",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Redshift SSL encryption in transit and how to configure it refer to the Encryption in transit section of the Amazon Redshift Cluster Management Guide",
                                "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/security-encryption-in-transit.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Analytics",
                            "AssetService": "Amazon Redshift",
                            "AssetComponent": "Cluster"
                        },
                        "Resources": [
                            {
                                "Type": "AwsRedshiftCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsRedshiftCluster": {
                                        "AvailabilityZone": clusterAz,
                                        "ClusterIdentifier": clusterId,
                                        "ClusterParameterGroups": [
                                            {
                                                "ParameterGroupName": clusterPgName
                                            }
                                        ],
                                        "ClusterSubnetGroupName": clusterSubnetGroupName,
                                        "ClusterVersion": clusterVersion,
                                        "DBName": dbName,
                                        "Endpoint": {
                                            "Address": endpointAddr,
                                            "Port": endpointPort
                                        },
                                        "NodeType": nodeType,
                                        "VpcId": vpcId
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

@registry.register_check("redshift")
def redshift_cluster_auto_snapshot_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.8] Amazon Redshift clusters should have automatic snapshots enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["AutomatedSnapshotRetentionPeriod"] == 0:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-automatic-snapshots-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Redshift.8] Amazon Redshift clusters should have automatic snapshots enabled",
                "Description": f"Redshift cluster {clusterId} does not automatic snapshots enabled. When automated snapshots are enabled for a cluster, Amazon Redshift periodically takes snapshots of that cluster. By default Amazon Redshift takes a snapshot about every eight hours or following every 5 GB per node of data changes, or whichever comes first. Alternatively, you can create a snapshot schedule to control when automated snapshots are taken. Automated snapshots are enabled by default when you create a cluster. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift automated snapshots and how to configure it refer to the Automated snapshots section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html#about-automated-snapshots",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-automatic-snapshots-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.8] Amazon Redshift clusters should have automatic snapshots enabled",
                "Description": f"Redshift cluster {clusterId} has automatic snapshots enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift automated snapshots and how to configure it refer to the Automated snapshots section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html#about-automated-snapshots",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("redshift")
def redshift_cluster_auto_version_upgrade_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.9] Amazon Redshift should have automatic upgrades to major versions enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_redshift_clusters(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterId = cluster["ClusterIdentifier"]
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"  
        clusterAz = cluster["AvailabilityZone"]
        clusterPgName = cluster["ClusterParameterGroups"][0]["ParameterGroupName"]
        clusterSubnetGroupName = cluster["ClusterSubnetGroupName"]
        clusterVersion = cluster["ClusterVersion"]
        dbName = cluster["DBName"]
        endpointAddr = cluster["Endpoint"]["Address"]
        endpointPort = cluster["Endpoint"]["Port"]
        nodeType = cluster["NodeType"]
        vpcId = cluster["VpcId"]
        if cluster["AllowVersionUpgrade"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-automatic-version-upgrade-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Redshift.9] Amazon Redshift should have automatic upgrades to major versions enabled",
                "Description": f"Redshift cluster {clusterId} does not have automatic major version upgrades enabled. Enabling automatic major version upgrades ensures that the latest major version updates to Amazon Redshift clusters are installed during the maintenance window. These updates might include security patches and bug fixes. Keeping up to date with patch installation is an important step in securing systems. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift automated version upgrades and maintenance windows refer to the Maintenance windows section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#rs-maintenance-windows",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/redshift-cluster-automatic-version-upgrade-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.9] Amazon Redshift should have automatic upgrades to major versions enabled",
                "Description": f"Redshift cluster {clusterId} has automatic major version upgrades enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift automated version upgrades and maintenance windows refer to the Maintenance windows section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#rs-maintenance-windows",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Redshift",
                    "AssetComponent": "Cluster"
                },
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRedshiftCluster": {
                                "AvailabilityZone": clusterAz,
                                "ClusterIdentifier": clusterId,
                                "ClusterParameterGroups": [
                                    {
                                        "ParameterGroupName": clusterPgName
                                    }
                                ],
                                "ClusterSubnetGroupName": clusterSubnetGroupName,
                                "ClusterVersion": clusterVersion,
                                "DBName": dbName,
                                "Endpoint": {
                                    "Address": endpointAddr,
                                    "Port": endpointPort
                                },
                                "NodeType": nodeType,
                                "VpcId": vpcId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding