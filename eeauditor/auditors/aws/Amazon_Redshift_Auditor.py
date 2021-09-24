'''
This file is part of ElectricEye.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
redshift = boto3.client("redshift")
# loop through redshift clusters
def describe_clusters(cache):
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = redshift.describe_clusters()
    return cache["describe_clusters"]

@registry.register_check("redshift")
def cluster_public_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.1] Redshift clusters should not be publicly accessible"""
    clusters = describe_clusters(cache=cache)
    myRedshiftClusters = clusters["Clusters"]
    for cluster in myRedshiftClusters:
        clusterId = str(cluster["ClusterIdentifier"])
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(cluster["PubliclyAccessible"]) == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-public-access-check",
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
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[Redshift.1] Redshift clusters should not be publicly accessible",
                "Description": "Redshift cluster "
                + clusterId
                + " is publicly accessible. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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
                "Id": clusterArn + "/redshift-public-access-check",
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
                "Title": "[Redshift.1] Redshift clusters should not be publicly accessible",
                "Description": "Redshift cluster " + clusterId + " is not publicly accessible.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying Redshift public access refer to the Modifying a Cluster section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-console.html#modify-cluster",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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

@registry.register_check("redshift")
def cluster_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.2] Redshift clusters should be encrypted"""
    clusters = describe_clusters(cache=cache)
    myRedshiftClusters = clusters["Clusters"]
    for cluster in myRedshiftClusters:
        clusterId = str(cluster["ClusterIdentifier"])
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(cluster["Encrypted"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-cluster-encryption-check",
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
                "Title": "[Redshift.2] Redshift clusters should be encrypted",
                "Description": "Redshift cluster "
                + clusterId
                + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-cluster-encryption-check",
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
                "Title": "[Redshift.2] Redshift clusters should be encrypted",
                "Description": "Redshift cluster " + clusterId + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift cluster encryption and how to configure it refer to the Amazon Redshift Database Encryption section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("redshift")
def cluster_enhanced_vpc_routing_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.3] Redshift clusters should utilize enhanced VPC routing"""
    clusters = describe_clusters(cache=cache)
    myRedshiftClusters = clusters["Clusters"]
    for cluster in myRedshiftClusters:
        clusterId = str(cluster["ClusterIdentifier"])
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(cluster["EnhancedVpcRouting"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-cluster-enhanced-vpc-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift.3] Redshift clusters should utilize enhanced VPC routing",
                "Description": "Redshift cluster "
                + clusterId
                + " is not utilizing enhanced VPC routing. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
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
                "Id": clusterArn + "/redshift-enhanced-vpc-routing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.3] Redshift clusters should utilize enhanced VPC routing",
                "Description": "Redshift cluster "
                + clusterId
                + " is utilizing enhanced VPC routing.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift Enhanced VPC routing and how to configure it refer to the Amazon Redshift Enhanced VPC Routing section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("redshift")
def cluster_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Redshift.4] Redshift clusters should have logging enabled"""
    clusters = describe_clusters(cache=cache)
    myRedshiftClusters = clusters["Clusters"]
    for cluster in myRedshiftClusters:
        clusterId = str(cluster["ClusterIdentifier"])
        clusterArn = f"arn:{awsPartition}:redshift:{awsRegion}:{awsAccountId}:cluster:{clusterId}"
        response = redshift.describe_logging_status(ClusterIdentifier=clusterId)
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(response["LoggingEnabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-cluster-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Redshift.4] Redshift clusters should have logging enabled",
                "Description": "Redshift cluster "
                + clusterId
                + " does not have logging enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clusterArn + "/redshift-cluster-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Redshift.4] Redshift clusters should have logging enabled",
                "Description": "Redshift cluster " + clusterId + " has logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Redshift logging and how to configure it refer to the Database Audit Logging section of the Amazon Redshift Cluster Management Guide",
                        "Url": "https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRedshiftCluster",
                        "Id": clusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"ClusterId": clusterId}},
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