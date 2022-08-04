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

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
dax = boto3.client("dax")

# loop through DAX clusters
def describe_clusters(cache):
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = dax.describe_clusters()
    return cache["describe_clusters"]

@registry.register_check("dax")
def dax_encryption_at_rest_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DAX.1] DynamoDB Accelerator (DAX) clusters should be encrypted at rest"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_clusters(cache)["Clusters"]:
        clusterName = cluster["ClusterName"]
        clusterArn = cluster["ClusterArn"]
        # this is a failing check
        if cluster["SSEDescription"]["Status"] != ("ENABLING" or "ENABLED"):
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/dax-encryption-at-rest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[DAX.1] DynamoDB Accelerator (DAX) clusters should be encrypted at rest",
                "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} is not encrypted at rest. Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage. Organizational policies, industry or government regulations, and compliance requirements might require the use of encryption at rest to protect your data. You can use encryption to increase the data security of your applications that are deployed in the cloud. With encryption at rest, the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard, also known as AES-256 encryption. DAX writes data to disk as part of propagating changes from the primary node to read replicas. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot enable or disable encryption at rest after a cluster has been created. You must re-create the cluster to enable encryption at rest if it was not enabled at creation. For more information refer to the DAX encryption at rest section of the Amazon DynamoDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDaxCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ClusterName": clusterName,
                                "TotalNodes": str(cluster["TotalNodes"]),
                                "NodeType": cluster["NodeType"],
                                "Status": cluster["Status"],
                                "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                "SubnetGroup": cluster["SubnetGroup"],
                                "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                "IamRoleArn": cluster["IamRoleArn"],
                                "ParameterGroupName": cluster["ParameterGroup"]["ParameterGroupName"]
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1", 
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/dax-encryption-at-rest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DAX.1] DynamoDB Accelerator (DAX) clusters should be encrypted at rest",
                "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} is encrypted at rest.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "You cannot enable or disable encryption at rest after a cluster has been created. You must re-create the cluster to enable encryption at rest if it was not enabled at creation. For more information refer to the DAX encryption at rest section of the Amazon DynamoDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDaxCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ClusterName": clusterName,
                                "TotalNodes": str(cluster["TotalNodes"]),
                                "NodeType": cluster["NodeType"],
                                "Status": cluster["Status"],
                                "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                "SubnetGroup": cluster["SubnetGroup"],
                                "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                "IamRoleArn": cluster["IamRoleArn"],
                                "ParameterGroupName": cluster["ParameterGroup"]["ParameterGroupName"]
                            }
                        }
                    }
                ],
                "Compliance": { 
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-1", 
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("dax")
def dax_encryption_in_transit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DAX.2] DynamoDB Accelerator (DAX) clusters should enforce encryption in transit"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_clusters(cache)["Clusters"]:
        clusterName = cluster["ClusterName"]
        clusterArn = cluster["ClusterArn"]
        # this is a failing check
        if cluster["ClusterEndpointEncryptionType"] == "NONE":
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/dax-encryption-in-transit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[DAX.2] DynamoDB Accelerator (DAX) clusters should enforce encryption in transit",
                "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} does not enforce encryption in transit. Amazon DynamoDB Accelerator (DAX) supports encryption in transit of data between your application and your DAX cluster, enabling you to use DAX in applications with stringent encryption requirements. Regardless of whether or not you choose encryption in transit, traffic between your application and your DAX cluster remains in your Amazon VPC. DAX encryption in transit adds to this baseline level of confidentiality, ensuring that all requests and responses between the application and the cluster are encrypted by transport level security (TLS), and connections to the cluster can be authenticated by verification of a cluster x509 certificate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Encryption in transit cannot be enabled on an existing DAX cluster. To use encryption in transit in an existing DAX application, create a new cluster with encryption in transit enabled, shift your application's traffic to it, then delete the old cluster. For more information on DAX encryption in transit refer to the DAX encryption in transit section of the Amazon DynamoDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionInTransit.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDaxCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ClusterName": clusterName,
                                "TotalNodes": str(cluster["TotalNodes"]),
                                "NodeType": cluster["NodeType"],
                                "Status": cluster["Status"],
                                "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                "SubnetGroup": cluster["SubnetGroup"],
                                "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                "IamRoleArn": cluster["IamRoleArn"],
                                "ParameterGroupName": cluster["ParameterGroup"]["ParameterGroupName"]
                            }
                        }
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
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding={
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/dax-encryption-in-transit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DAX.2] DynamoDB Accelerator (DAX) clusters should enforce encryption in transit",
                "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} enforces encryption in transit.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Encryption in transit cannot be enabled on an existing DAX cluster. To use encryption in transit in an existing DAX application, create a new cluster with encryption in transit enabled, shift your application's traffic to it, then delete the old cluster. For more information on DAX encryption in transit refer to the DAX encryption in transit section of the Amazon DynamoDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionInTransit.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDaxCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ClusterName": clusterName,
                                "TotalNodes": str(cluster["TotalNodes"]),
                                "NodeType": cluster["NodeType"],
                                "Status": cluster["Status"],
                                "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                "SubnetGroup": cluster["SubnetGroup"],
                                "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                "IamRoleArn": cluster["IamRoleArn"],
                                "ParameterGroupName": cluster["ParameterGroup"]["ParameterGroupName"]
                            }
                        }
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
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("dax")
def dax_encryption_in_transit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DAX.3] DynamoDB Accelerator (DAX) clusters should enforce a cache TTL value"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_clusters(cache)["Clusters"]:
        clusterName = cluster["ClusterName"]
        clusterArn = cluster["ClusterArn"]
        pgName = cluster["ParameterGroup"]["ParameterGroupName"]
        # retrieve the parameters within the parameter group associated with the cluster
        for parameter in dax.describe_parameters(ParameterGroupName=pgName)["Parameters"]:
            if parameter["ParameterName"] == "record-ttl-millis":
                # this is a failing check
                if parameter["ParameterValue"] == "0":
                    finding={
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/dax-cache-ttl-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[DAX.3] DynamoDB Accelerator (DAX) clusters should enforce cache Time-to-Live (TTL)",
                        "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} does not enforce cache Time-to-Live (TTL). DAX maintains an item cache to store the results from GetItem and BatchGetItem operations. The items in the cache represent eventually consistent data from DynamoDB, and are stored by their primary key values. The item cache has a Time to Live (TTL) setting, which is 5 minutes by default. DAX assigns a timestamp to every item that it writes to the item cache. An item expires if it has remained in the cache for longer than the TTL setting. If you issue a GetItem request on an expired item, this is considered a cache miss, and DAX sends the GetItem request to DynamoDB. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on DAX caching refer to the Item cache subsection of the DAX: How it works section of the Amazon DynamoDB Developer Guide",
                                "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAX.concepts.html#DAX.concepts.item-cache"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsDaxCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "ClusterName": clusterName,
                                        "TotalNodes": str(cluster["TotalNodes"]),
                                        "NodeType": cluster["NodeType"],
                                        "Status": cluster["Status"],
                                        "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                        "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                        "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                        "SubnetGroup": cluster["SubnetGroup"],
                                        "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                        "IamRoleArn": cluster["IamRoleArn"],
                                        "ParameterGroupName": pgName
                                    }
                                }
                            }
                        ],
                        "Compliance": { 
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF ID.BE-5",
                                "NIST CSF PR.PT-5",
                                "NIST SP 800-53 CP-2",
                                "NIST SP 800-53 CP-11",
                                "NIST SP 800-53 SA-13",
                                "NIST SP 800-53 SA14",
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
                # this is a passing check
                else:
                    finding={
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/dax-cache-ttl-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[DAX.3] DynamoDB Accelerator (DAX) clusters should enforce cache Time-to-Live (TTL)",
                        "Description": f"DynamoDB Accelerator (DAX) cluster {clusterName} enforces cache Time-to-Live (TTL).",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on DAX caching refer to the Item cache subsection of the DAX: How it works section of the Amazon DynamoDB Developer Guide",
                                "Url": "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAX.concepts.html#DAX.concepts.item-cache"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsDaxCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "ClusterName": clusterName,
                                        "TotalNodes": str(cluster["TotalNodes"]),
                                        "NodeType": cluster["NodeType"],
                                        "Status": cluster["Status"],
                                        "Address": cluster["ClusterDiscoveryEndpoint"]["Address"],
                                        "Port": str(cluster["ClusterDiscoveryEndpoint"]["Port"]),
                                        "URL": cluster["ClusterDiscoveryEndpoint"]["URL"],
                                        "SubnetGroup": cluster["SubnetGroup"],
                                        "SecurityGroupIdentifier": cluster["SecurityGroups"][0]["SecurityGroupIdentifier"],
                                        "IamRoleArn": cluster["IamRoleArn"],
                                        "ParameterGroupName": pgName
                                    }
                                }
                            }
                        ],
                        "Compliance": { 
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF ID.BE-5",
                                "NIST CSF PR.PT-5",
                                "NIST SP 800-53 CP-2",
                                "NIST SP 800-53 CP-11",
                                "NIST SP 800-53 SA-13",
                                "NIST SP 800-53 SA14",
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
                # close the loop once the correct parameter is found
                break
            else:
                continue