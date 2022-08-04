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
                        "Text": "DAX Cluster encryption at rest options cannot be changed after creation and must be rebuilt. For more information refer to the DAX encryption at rest section of the Amazon DynamoDB Developer Guide",
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
                                "Port": cluster["ClusterDiscoveryEndpoint"]["Port"],
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
                        "Text": "DAX Cluster encryption at rest options cannot be changed after creation and must be rebuilt. For more information refer to the DAX encryption at rest section of the Amazon DynamoDB Developer Guide",
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
                                "Port": cluster["ClusterDiscoveryEndpoint"]["Port"],
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