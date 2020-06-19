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

documentdb = boto3.client("docdb")


def describe_db_instances(cache):
    response = cache.get("describe_db_instances")
    if response:
        return response
    cache["describe_db_instances"] = documentdb.describe_db_instances()
    return cache["describe_db_instances"]


@registry.register_check("docdb")
def docdb_public_instance_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_db_instances(cache)
    myDocDbs = response["DBInstances"]
    for docdb in myDocDbs:
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        publicAccessCheck = str(docdb["PubliclyAccessible"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if publicAccessCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbArn + "/docdb-public-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocDb.1] DocumentDB instances should not be exposed to the public",
                "Description": "DocumentDB instance "
                + docdbId
                + " is exposed to the public. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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
                "Id": docdbArn + "/docdb-public-access",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocDb.1] DocumentDB instances should not be exposed to the public",
                "Description": "DocumentDB instance " + docdbId + " is not exposed to the public.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be public refer to the Connecting to an Amazon DocumentDB Cluster from Outside an Amazon VPC section in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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
def docdb_instance_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_db_instances(cache)
    myDocDbs = response["DBInstances"]
    for docdb in myDocDbs:
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        encryptionCheck = str(docdb["StorageEncrypted"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if encryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbArn + "/docdb-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocDb.2] DocumentDB instances should be encrypted",
                "Description": "DocumentDB instance "
                + docdbId
                + " is not encrypted. You encrypt data at rest in your Amazon DocumentDB cluster by specifying the storage encryption option when you create your cluster. Storage encryption is enabled cluster-wide and is applied to all instances, including the primary instance and any replicas. It is also applied to your cluster’s storage volume, data, indexes, logs, automated backups, and snapshots. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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
                "Id": docdbArn + "/docdb-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
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
                "Title": "[DocDb.2] DocumentDB instances should be encrypted",
                "Description": "DocumentDB instance " + docdbId + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB is not intended to be unencrypted refer to Encrypting Amazon DocumentDB Data at Rest in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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


@registry.register_check("docdb")
def docdb_instance_audit_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_db_instances(cache)
    myDocDbs = response["DBInstances"]
    for docdb in myDocDbs:
        docdbId = str(docdb["DBInstanceIdentifier"])
        docdbArn = str(docdb["DBInstanceArn"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            # this is a passing check
            logCheck = str(docdb["EnabledCloudwatchLogsExports"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbArn + "/docdb-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DocDb.3] DocumentDB instances should have audit logging configured",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbArn + "/docdb-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DocDb.3] DocumentDB instances should have audit logging configured",
                "Description": "DocumentDB instance "
                + docdbId
                + " does not have audit logging configured. Profiler is useful for monitoring the slowest operations on your cluster to help you improve individual query performance and overall cluster performance. When enabled, operations are logged to Amazon CloudWatch Logs and you can use CloudWatch Insight to analyze, monitor, and archive your Amazon DocumentDB profiling data. Refer to the remediation instructions if this configuration is not intended",
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
                        "Details": {"Other": {"instanceId": docdbId}},
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


@registry.register_check("docdb")
def docdb_cluster_multiaz_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # find document db clusters
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response["DBClusters"]
    for docdbcluster in myDocDbClusters:
        docdbclusterId = str(docdbcluster["DBClusterIdentifier"])
        docdbClusterArn = str(docdbcluster["DBClusterArn"])
        multiAzCheck = str(docdbcluster["MultiAZ"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if multiAzCheck == "False":
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
                "Title": "[DocDb.4] DocumentDB clusters should be configured for Multi-AZ",
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
                        "Details": {"Other": {"clusterId": docdbclusterId}},
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
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
                "Title": "[DocDb.4] DocumentDB clusters should be configured for Multi-AZ",
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
                        "Details": {"Other": {"clusterId": docdbclusterId}},
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("docdb")
def docdb_cluster_deletion_protection_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # find document db instances
    response = documentdb.describe_db_clusters(MaxRecords=100)
    myDocDbClusters = response["DBClusters"]
    for docdbcluster in myDocDbClusters:
        docdbclusterId = str(docdbcluster["DBClusterIdentifier"])
        docdbClusterArn = str(docdbcluster["DBClusterArn"])
        multiAzCheck = str(docdbcluster["MultiAZ"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if multiAzCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbClusterArn + "/docdb-cluster-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DocDb.5] DocumentDB clusters should have deletion protection enabled",
                "Description": "DocumentDB cluster "
                + docdbclusterId
                + " does not have deletion protection enabled. To protect your cluster from accidental deletion, you can enable deletion protection. Deletion protection is enabled by default when you create a cluster using the console. However, deletion protection is disabled by default if you create a cluster using the AWS CLI. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"clusterId": docdbclusterId}},
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": docdbClusterArn + "/docdb-cluster-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DocDb.5] DocumentDB clusters should have deletion protection enabled",
                "Description": "DocumentDB cluster "
                + docdbclusterId
                + " has deletion protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your DocumentDB cluster should have deletion protection enabled refer to the Deletion Protection section in the Amazon DocumentDB Developer Guide",
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
                        "Details": {"Other": {"clusterId": docdbclusterId}},
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("docdb")
def documentdb_parameter_group_audit_log_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = documentdb.describe_db_cluster_parameter_groups()
    dbClusterParameters = response["DBClusterParameterGroups"]
    for parametergroup in dbClusterParameters:
        if str(parametergroup["DBParameterGroupFamily"]) == "docdb3.6":
            parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
            parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
            response = documentdb.describe_db_cluster_parameters(
                DBClusterParameterGroupName=parameterGroupName
            )
            for parameters in response["Parameters"]:
                if str(parameters["ParameterName"]) == "audit_logs":
                    auditLogCheck = str(parameters["ParameterValue"])
                    # ISO Time
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if auditLogCheck == "disabled":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": parameterGroupArn
                            + "/docdb-cluster-parameter-audit-logging-check",
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
                            "Title": "[DocDb.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases",
                            "Description": "DocumentDB cluster parameter group "
                            + parameterGroupName
                            + " does not enforce audit logging. Examples of logged events include successful and failed authentication attempts, dropping a collection in a database, or creating an index. By default, auditing is disabled on Amazon DocumentDB and requires that you opt in to use this feature. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"ParameterGroupName": parameterGroupName}
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
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": parameterGroupArn
                            + "/docdb-cluster-parameter-audit-logging-check",
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
                            "Title": "[DocDb.6] DocumentDB cluster parameter groups should enforce audit logging for DocumentDB databases",
                            "Description": "DocumentDB cluster parameter group "
                            + parameterGroupName
                            + " enforces audit logging.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have audit logging enabled refer to the Enabling Auditing section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html#event-auditing-enabling-auditing",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"ParameterGroupName": parameterGroupName}
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
                else:
                    pass
        else:
            pass


@registry.register_check("docdb")
def documentdb_parameter_group_tls_enforcement_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = documentdb.describe_db_cluster_parameter_groups()
    dbClusterParameters = response["DBClusterParameterGroups"]
    for parametergroup in dbClusterParameters:
        if str(parametergroup["DBParameterGroupFamily"]) == "docdb3.6":
            parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
            parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
            response = documentdb.describe_db_cluster_parameters(
                DBClusterParameterGroupName=parameterGroupName
            )
            for parameters in response["Parameters"]:
                if str(parameters["ParameterName"]) == "tls":
                    tlsEnforcementCheck = str(parameters["ParameterValue"])
                    # ISO Time
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if tlsEnforcementCheck == "disabled":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": parameterGroupArn
                            + "/docdb-cluster-parameter-tls-connections-check",
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
                            "Title": "[DocDb.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases",
                            "Description": "DocumentDB cluster parameter group "
                            + parameterGroupName
                            + " does not enforce TLS connections. When encryption in transit is enabled, secure connections using TLS are required to connect to the cluster. Encryption in transit for an Amazon DocumentDB cluster is managed via the TLS parameter in a cluster parameter group. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"parameterGroupName": parameterGroupName}
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
                            "Id": parameterGroupArn
                            + "/docdb-cluster-parameter-tls-connections-check",
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
                            "Title": "[DocDb.7] DocumentDB cluster parameter groups should enforce TLS connections to DocumentDB databases",
                            "Description": "DocumentDB cluster parameter group "
                            + parameterGroupName
                            + " enforces TLS connections.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster should have encryption in transit enforced refer to the Managing Amazon DocumentDB Cluster TLS Settings section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": parameterGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {"parameterGroupName": parameterGroupName}
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
                else:
                    pass
        else:
            pass


@registry.register_check("docdb")
def documentdb_cluster_snapshot_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = documentdb.describe_db_clusters(Filters=[{"Name": "engine", "Values": ["docdb"]}])
    for clusters in response["DBClusters"]:
        clusterId = str(clusters["DBClusterIdentifier"])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response["DBClusterSnapshots"]:
            clusterSnapshotId = str(snapshots["DBClusterSnapshotIdentifier"])
            clusterSnapshotArn = str(snapshots["DBClusterSnapshotArn"])
            encryptionCheck = str(snapshots["StorageEncrypted"])
            # ISO Time
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if encryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clusterSnapshotArn + "/docdb-cluster-snapshot-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterSnapshotArn,
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
                    "Title": "[DocDb.8] DocumentDB cluster snapshots should be encrypted",
                    "Description": "DocumentDB cluster snapshot "
                    + clusterSnapshotId
                    + " is not encrypted. You encrypt data at rest in your Amazon DocumentDB cluster by specifying the storage encryption option when you create your cluster. Storage encryption is enabled cluster-wide and is applied to all instances, including the primary instance and any replicas. It is also applied to your cluster’s storage volume, data, indexes, logs, automated backups, and snapshots. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": clusterSnapshotArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"snapshotId": clusterSnapshotId}},
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
                    "Id": clusterSnapshotArn + "/docdb-cluster-snapshot-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterSnapshotArn,
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
                    "Title": "[DocDb.8] DocumentDB cluster snapshots should be encrypted",
                    "Description": "DocumentDB cluster snapshot "
                    + clusterSnapshotId
                    + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your DocumentDB cluster snapshot should be encrypted refer to the Limitations for Amazon DocumentDB Encrypted Clusters section in the Amazon DocumentDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html#encryption-at-rest-limits",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": clusterSnapshotArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"snapshotId": clusterSnapshotId}},
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


@registry.register_check("docdb")
def documentdb_cluster_snapshot_public_share_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = documentdb.describe_db_clusters(Filters=[{"Name": "engine", "Values": ["docdb"]}])
    for clusters in response["DBClusters"]:
        clusterId = str(clusters["DBClusterIdentifier"])
        response = documentdb.describe_db_cluster_snapshots(DBClusterIdentifier=clusterId)
        for snapshots in response["DBClusterSnapshots"]:
            clusterSnapshotId = str(snapshots["DBClusterSnapshotIdentifier"])
            clusterSnapshotArn = str(snapshots["DBClusterSnapshotArn"])
            response = documentdb.describe_db_cluster_snapshot_attributes(
                DBClusterSnapshotIdentifier=clusterSnapshotId
            )
            for snapshotattributes in response["DBClusterSnapshotAttributesResult"][
                "DBClusterSnapshotAttributes"
            ]:
                if str(snapshotattributes["AttributeName"]) == "restore":
                    valueCheck = str(snapshotattributes["AttributeValues"])
                    # ISO Time
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if valueCheck == "['all']":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": clusterSnapshotArn
                            + "/docdb-cluster-snapshot-public-share-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterSnapshotArn,
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
                            "Title": "[DocDb.9] DocumentDB cluster snapshots should not be publicly shared",
                            "Description": "DocumentDB cluster snapshot "
                            + clusterSnapshotId
                            + " is publicly shared. You can share a manual snapshot with up to 20 other AWS accounts. You can also share an unencrypted manual snapshot as public, which makes the snapshot available to all accounts. Take care when sharing a snapshot as public so that none of your private information is included in any of your public snapshots. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": clusterSnapshotArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"snapshotId": clusterSnapshotId}},
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
                            "Id": clusterSnapshotArn
                            + "/docdb-cluster-snapshot-public-share-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": clusterSnapshotArn,
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
                            "Title": "[DocDb.9] DocumentDB cluster snapshots should not be publicly shared",
                            "Description": "DocumentDB cluster snapshot "
                            + clusterSnapshotId
                            + " is not publicly shared, however, it may be shared with other accounts. You should periodically review who has snapshots shared with them to ensure they are still authorized",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "If your DocumentDB cluster snapshot should not be publicly shared refer to the Sharing Amazon DocumentDB Cluster Snapshots section in the Amazon DocumentDB Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/documentdb/latest/developerguide/backup-restore.db-cluster-snapshot-share.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "Other",
                                    "Id": clusterSnapshotArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"snapshotId": clusterSnapshotId}},
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
                else:
                    pass
