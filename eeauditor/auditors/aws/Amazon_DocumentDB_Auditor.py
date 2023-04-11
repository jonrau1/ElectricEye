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

def describe_db_instances(cache, session):
    documentdb = session.client("docdb")
    docdbInstances = []
    response = cache.get("describe_db_instances")
    if response:
        return response
    paginator = documentdb.get_paginator('describe_db_instances')
    if paginator:
        # paginate all DB instances (since every single RDS-namespace is returned)
        # and only add pages that are within the docdb engine
        for page in paginator.paginate():
            for docdbi in page["DBInstances"]:
                if docdbi["Engine"] == "docdb":
                    docdbInstances.append(docdbi)
    cache["describe_db_instances"] = docdbInstances
    return cache["describe_db_instances"]

def describe_db_clusters(cache, session):
    documentdb = session.client("docdb")
    response = cache.get("describe_db_clusters")
    if response:
        return response
    cache["describe_db_clusters"] = documentdb.describe_db_clusters(
        Filters=[{"Name": "engine", "Values": ["docdb"]}]
    )
    return cache["describe_db_clusters"]

def describe_db_cluster_parameter_groups(cache, session):
    documentdb = session.client("docdb")
    response = cache.get("describe_db_cluster_parameter_groups")
    if response:
        return response
    cache["describe_db_cluster_parameter_groups"] = documentdb.describe_db_cluster_parameter_groups()
    return cache["describe_db_cluster_parameter_groups"]

@registry.register_check("docdb")
def docdb_public_instance_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.1] DocumentDB instances should not be exposed to the public"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdb in describe_db_instances(cache, session):
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        publicAccessCheck = str(docdb["PubliclyAccessible"])
        # this is a failing check
        if publicAccessCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-public-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[DocumentDB.1] DocumentDB instances should not be exposed to the public",
                "Description": f"DocumentDB instance {docdbId} is exposed to the public. Amazon DocumentDB (with MongoDB compatibility) clusters are deployed within an Amazon Virtual Private Cloud (Amazon VPC). They can be accessed directly by Amazon EC2 instances or other AWS services that are deployed in the same Amazon VPC. Additionally, Amazon DocumentDB can be accessed by EC2 instances or other AWS services in different VPCs in the same AWS Region or other Regions via VPC peering. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/connect-from-outside-a-vpc.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
                            }
                        }
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-public-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocumentDB.1] DocumentDB instances should not be exposed to the public",
                "Description": f"DocumentDB instance {docdbId} is not exposed to the public.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/connect-from-outside-a-vpc.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
                            }
                        }
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

@registry.register_check("docdb")
def docdb_instance_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.2] DocumentDB instances should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdb in describe_db_instances(cache, session):
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        encryptionCheck = str(docdb["StorageEncrypted"])
        # this is a failing check
        if encryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocumentDB.2] DocumentDB instances should be encrypted",
                "Description": f"DocumentDB instance {docdbId} is not encrypted. You encrypt data at rest in your Amazon DocumentDB cluster by specifying the storage encryption option when you create your cluster. Storage encryption is enabled cluster-wide and is applied to all instances, including the primary instance and any replicas. It is also applied to your cluster's storage volume, data, indexes, logs, automated backups, and snapshots. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocumentDB.2] DocumentDB instances should be encrypted",
                "Description": f"DocumentDB instance {docdbId} is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
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

@registry.register_check("docdb")
def docdb_instance_audit_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.3] DocumentDB instances should have audit logging configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdb in describe_db_instances(cache, session):
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        # this is a passing check
        try:
            # we wont actually be doing anything with this, hence no variable
            docdb["EnabledCloudwatchLogsExports"]
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DocumentDB.3] DocumentDB instances should have audit logging configured",
                "Description": "DocumentDB instance " + docdbId + " has audit logging configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on DocumentDB audit logging refer to the Auditing Amazon DocumentDB Events section in the Amazon DocumentDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
                            }
                        }
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
        # this is a failing check
        except KeyError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbArn}/docdb-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DocumentDB.3] DocumentDB instances should have audit logging configured",
                "Description": f"DocumentDB instance {docdbId} does not have audit logging configured. Profiler is useful for monitoring the slowest operations on your cluster to help you improve individual query performance and overall cluster performance. When enabled, operations are logged to Amazon CloudWatch Logs and you can use CloudWatch Insight to analyze, monitor, and archive your Amazon DocumentDB profiling data. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on DocumentDB audit logging refer to the Auditing Amazon DocumentDB Events section in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbInstance",
                        "Id": docdbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": docdbId,
                                "DBInstanceClass": docdb["DBInstanceClass"],
                                "Engine": docdb["Engine"],
                                "Address": docdb["Endpoint"]["Address"],
                                "Port": str(docdb["Endpoint"]["Port"]),
                                "DBSubnetGroupName": docdb["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": docdb["DBSubnetGroup"]["VpcId"],
                                "EngineVersion": docdb["EngineVersion"],
                                "DBClusterIdentifier": docdb["DBClusterIdentifier"]
                            }
                        }
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("docdb")
def docdb_cluster_multiaz_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.4] DocumentDB clusters should be configured for Multi-AZ"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdbcluster in describe_db_clusters(cache, session)["DBClusters"]:
        docdbclusterId = str(docdbcluster["DBClusterIdentifier"])
        docdbClusterArn = str(docdbcluster["DBClusterArn"])
        multiAzCheck = str(docdbcluster["MultiAZ"])
        if multiAzCheck == "False":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbClusterArn + "/docdb-cluster-multi-az-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbclusterId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DocumentDB.4] DocumentDB clusters should be configured for Multi-AZ",
                "Description": "DocumentDB cluster "
                + docdbclusterId
                + " is not configured for Multi-AZ. Amazon DocumentDB helps ensure that there are instances available in your cluster in the unlikely event of an Availability Zone failure. The cluster volume for your Amazon DocumentDB cluster always spans three Availability Zones to provide durable storage with less possibility of data loss. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should be in Multi-AZ configuration refer to the Understanding Amazon DocumentDB Cluster Fault Tolerance section in the Amazon DocumentDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-fault-tolerance.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbCluster",
                        "Id": docdbClusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBClusterIdentifier": docdbclusterId,
                                "DBClusterParameterGroup": docdbcluster["DBClusterParameterGroup"],
                                "DBSubnetGroup": docdbcluster["DBSubnetGroup"],
                                "Status": docdbcluster["Status"],
                                "Endpoint": docdbcluster["Endpoint"],
                                "Engine": docdbcluster["Engine"],
                                "EngineVersion": docdbcluster["EngineVersion"],
                                "Port": str(docdbcluster["Port"]),
                                "MasterUsername": docdbcluster["MasterUsername"],
                                "DbClusterResourceId": docdbcluster["DbClusterResourceId"]
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
                        "NIST SP 800-53 SA-14",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC3.1",
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
                "Id": docdbClusterArn + "/docdb-cluster-multi-az-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DocumentDB.4] DocumentDB clusters should be configured for Multi-AZ",
                "Description": "DocumentDB cluster "
                + docdbclusterId
                + " is configured for Multi-AZ.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should be in Multi-AZ configuration refer to the Understanding Amazon DocumentDB Cluster Fault Tolerance section in the Amazon DocumentDB Developer Guide",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-fault-tolerance.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbCluster",
                        "Id": docdbClusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBClusterIdentifier": docdbclusterId,
                                "DBClusterParameterGroup": docdbcluster["DBClusterParameterGroup"],
                                "DBSubnetGroup": docdbcluster["DBSubnetGroup"],
                                "Status": docdbcluster["Status"],
                                "Endpoint": docdbcluster["Endpoint"],
                                "Engine": docdbcluster["Engine"],
                                "EngineVersion": docdbcluster["EngineVersion"],
                                "Port": str(docdbcluster["Port"]),
                                "MasterUsername": docdbcluster["MasterUsername"],
                                "DbClusterResourceId": docdbcluster["DbClusterResourceId"]
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
                        "NIST SP 800-53 SA-14",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC3.1",
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

@registry.register_check("docdb")
def docdb_cluster_deletion_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.5] DocumentDB clusters should have deletion protection enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdbcluster in describe_db_clusters(cache, session)["DBClusters"]:
        docdbclusterId = str(docdbcluster["DBClusterIdentifier"])
        docdbClusterArn = str(docdbcluster["DBClusterArn"])
        multiAzCheck = str(docdbcluster["MultiAZ"])
        # this is a failing check
        if multiAzCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbClusterArn}/docdb-cluster-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DocumentDB.5] DocumentDB clusters should have deletion protection enabled",
                "Description": f"DocumentDB cluster {docdbclusterId} does not have deletion protection enabled. To protect your cluster from accidental deletion, you can enable deletion protection. Deletion protection is enabled by default when you create a cluster using the console. However, deletion protection is disabled by default if you create a cluster using the AWS CLI. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html#db-cluster-deletion-protection",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbCluster",
                        "Id": docdbClusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBClusterIdentifier": docdbclusterId,
                                "DBClusterParameterGroup": docdbcluster["DBClusterParameterGroup"],
                                "DBSubnetGroup": docdbcluster["DBSubnetGroup"],
                                "Status": docdbcluster["Status"],
                                "Endpoint": docdbcluster["Endpoint"],
                                "Engine": docdbcluster["Engine"],
                                "EngineVersion": docdbcluster["EngineVersion"],
                                "Port": str(docdbcluster["Port"]),
                                "MasterUsername": docdbcluster["MasterUsername"],
                                "DbClusterResourceId": docdbcluster["DbClusterResourceId"]
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
                        "NIST SP 800-53 SA-14",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC3.1",
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbClusterArn}/docdb-cluster-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DocumentDB.5] DocumentDB clusters should have deletion protection enabled",
                "Description": f"DocumentDB cluster {docdbclusterId} has deletion protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html#db-cluster-deletion-protection",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsDocumentDbCluster",
                        "Id": docdbClusterArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBClusterIdentifier": docdbclusterId,
                                "DBClusterParameterGroup": docdbcluster["DBClusterParameterGroup"],
                                "DBSubnetGroup": docdbcluster["DBSubnetGroup"],
                                "Status": docdbcluster["Status"],
                                "Endpoint": docdbcluster["Endpoint"],
                                "Engine": docdbcluster["Engine"],
                                "EngineVersion": docdbcluster["EngineVersion"],
                                "Port": str(docdbcluster["Port"]),
                                "MasterUsername": docdbcluster["MasterUsername"],
                                "DbClusterResourceId": docdbcluster["DbClusterResourceId"]
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
                        "NIST SP 800-53 SA-14",
                        "AICPA TSC A1.2",
                        "AICPA TSC CC3.1",
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

@registry.register_check("docdb")
def documentdb_parameter_group_audit_log_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases"""
    documentdb = session.client("docdb")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for parametergroup in describe_db_cluster_parameter_groups(cache, session)["DBClusterParameterGroups"]:
        if str(parametergroup["DBParameterGroupFamily"]) == ("docdb3.6" or "docdb4.0"):
            parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
            parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
            # Parse the parameters in the PG
            response = documentdb.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
            for parameters in response["Parameters"]:
                if str(parameters["ParameterName"]) == "audit_logs":
                    auditLogCheck = str(parameters["ParameterValue"])
                    if auditLogCheck == "disabled":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{parameterGroupArn}/docdb-cluster-parameter-audit-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": parameterGroupArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[DocumentDB.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases",
                            "Description": f"DocumentDB cluster parameter group {parameterGroupName} does not enforce audit logging. Examples of logged events include successful and failed authentication attempts, dropping a collection in a database, or creating an index. By default, auditing is disabled on Amazon DocumentDB and requires that you opt in to use this feature. Refer to the remediation instructions to remediate this behavior.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterParameterGroup",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"DBClusterParameterGroupName": parameterGroupName}
                                    }
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
                                    "ISO 27001:2013 A.16.1.7"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{parameterGroupArn}/docdb-cluster-parameter-audit-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": parameterGroupArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[DocumentDB.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases",
                            "Description": f"DocumentDB cluster parameter group {parameterGroupName} enforces audit logging.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterParameterGroup",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"DBClusterParameterGroupName": parameterGroupName}
                                    }
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
                                    "ISO 27001:2013 A.16.1.7"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # complete the loop
                    break
                else:
                    continue
        else:
            continue

@registry.register_check("docdb")
def documentdb_parameter_group_tls_enforcement_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases"""
    documentdb = session.client("docdb")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for parametergroup in describe_db_cluster_parameter_groups(cache, session)["DBClusterParameterGroups"]:
        if str(parametergroup["DBParameterGroupFamily"]) == ("docdb3.6" or "docdb4.0"):
            parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
            parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
            # Parse the parameters in the PG
            response = documentdb.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
            for parameters in response["Parameters"]:
                if str(parameters["ParameterName"]) == "tls":
                    tlsEnforcementCheck = str(parameters["ParameterValue"])
                    # this is a failing check
                    if tlsEnforcementCheck == "disabled":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{parameterGroupArn}/docdb-cluster-parameter-tls-connections-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": parameterGroupArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[DocumentDB.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases",
                            "Description": f"DocumentDB cluster parameter group {parameterGroupName} does not enforce TLS connections. When encryption in transit is enabled, secure connections using TLS are required to connect to the cluster. Encryption in transit for an Amazon DocumentDB cluster is managed via the TLS parameter in a cluster parameter group. Refer to the remediation instructions to remediate this behavior.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterParameterGroup",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"DBClusterParameterGroupName": parameterGroupName}
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
                                    "ISO 27001:2013 A.14.1.3"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    # this is a passing check
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{parameterGroupArn}/docdb-cluster-parameter-tls-connections-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": parameterGroupArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[DocumentDB.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases",
                            "Description": f"DocumentDB cluster parameter group {parameterGroupName} enforces TLS connections.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterParameterGroup",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"DBClusterParameterGroupName": parameterGroupName}
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
                                    "ISO 27001:2013 A.14.1.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # complete the loop
                    break
                else:
                    continue
        else:
            continue

@registry.register_check("docdb")
def documentdb_cluster_snapshot_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.8] DocumentDB cluster snapshots should be encrypted"""
    documentdb = session.client("docdb")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdbcluster in describe_db_clusters(cache, session)["DBClusters"]:
        clusterId = str(docdbcluster["DBClusterIdentifier"])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response["DBClusterSnapshots"]:
            clusterSnapshotId = str(snapshots["DBClusterSnapshotIdentifier"])
            clusterSnapshotArn = str(snapshots["DBClusterSnapshotArn"])
            encryptionCheck = str(snapshots["StorageEncrypted"])
            # this is a failing check
            if encryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{clusterSnapshotArn}/docdb-cluster-snapshot-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterSnapshotArn,
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
                    "Title": "[DocumentDB.8] DocumentDB cluster snapshots should be encrypted",
                    "Description": f"DocumentDB cluster snapshot {clusterSnapshotId} is not encrypted. You encrypt data at rest in your Amazon DocumentDB cluster by specifying the storage encryption option when you create your cluster. Storage encryption is enabled cluster-wide and is applied to all instances, including the primary instance and any replicas. It is also applied to your cluster's storage volume, data, indexes, logs, automated backups, and snapshots. Refer to the remediation instructions to remediate this behavior.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsDocumentDbClusterSnapshot",
                            "Id": clusterSnapshotArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"DBClusterSnapshotIdentifier": clusterSnapshotId}}
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
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{clusterSnapshotArn}/docdb-cluster-snapshot-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterSnapshotArn,
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
                    "Title": "[DocumentDB.8] DocumentDB cluster snapshots should be encrypted",
                    "Description": f"DocumentDB cluster snapshot {clusterSnapshotId} is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsDocumentDbClusterSnapshot",
                            "Id": clusterSnapshotArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"DBClusterSnapshotIdentifier": clusterSnapshotId}}
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

@registry.register_check("docdb")
def documentdb_cluster_snapshot_public_share_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DocumentDB.9] DocumentDB cluster snapshots should not be publicly shared"""
    documentdb = session.client("docdb")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdbcluster in describe_db_clusters(cache, session)["DBClusters"]:
        clusterId = str(docdbcluster["DBClusterIdentifier"])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response["DBClusterSnapshots"]:
            clusterSnapshotId = str(snapshots["DBClusterSnapshotIdentifier"])
            clusterSnapshotArn = str(snapshots["DBClusterSnapshotArn"])
            response = documentdb.describe_db_cluster_snapshot_attributes(DBClusterSnapshotIdentifier=clusterSnapshotId)
            for snapshotattributes in response["DBClusterSnapshotAttributesResult"]["DBClusterSnapshotAttributes"]:
                if str(snapshotattributes["AttributeName"]) == "restore":
                    # list comprehension to see if "all" is within the attributes - which means "all of everyone on AWS" lol...
                    # this is a failing check
                    if "all" in snapshotattributes["AttributeValues"]:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{clusterSnapshotArn}/docdb-cluster-snapshot-public-share-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterSnapshotArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "CRITICAL"},
                            "Confidence": 99,
                            "Title": "[DocumentDB.9] DocumentDB cluster snapshots should not be publicly shared",
                            "Description": f"DocumentDB cluster snapshot {clusterSnapshotId} is publicly shared. You can share a manual snapshot with up to 20 other AWS accounts. You can also share an unencrypted manual snapshot as public, which makes the snapshot available to all accounts. Take care when sharing a snapshot as public so that none of your private information is included in any of your public snapshots. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterSnapshot",
                                    "Id": clusterSnapshotArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"DBClusterSnapshotIdentifier": clusterSnapshotId}}
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
                    # this is a passing check
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{clusterSnapshotArn}/docdb-cluster-snapshot-public-share-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterSnapshotArn,
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
                            "Title": "[DocumentDB.9] DocumentDB cluster snapshots should not be publicly shared",
                            "Description": f"DocumentDB cluster snapshot {clusterSnapshotId} is not publicly shared, however, it may be shared with other accounts. You should periodically review who has snapshots shared with them to ensure they are still authorized",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsDocumentDbClusterSnapshot",
                                    "Id": clusterSnapshotArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"DBClusterSnapshotIdentifier": clusterSnapshotId}}
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
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # complete the loop
                    break
                else:
                    continue