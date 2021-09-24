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

# [MemoryDB.1] MemoryDB Clusters should configured to use encryption in transit HIGH
# [MemoryDB.2] MemoryDB Clusters should used KMS CMKs for encryption at rest MEDIUM
# [MemoryDB.3] MemoryDB Clusters should be configured for automatic minor version updates LOW
# [MemoryDB.4] MemoryDB Clusters should be actively monitored with SNS LOW
# [MemoryDB.5] MemoryDB Cluster Users with administrative privileges should be validated HIGH
# [MemoryDB.6] MemoryDB Cluster Users should require additional password authentication MEDIUM 

registry = CheckRegister()

memorydb = boto3.client("memorydb")

def describe_clusters(cache):
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = memorydb.describe_clusters(MaxResults=100,ShowShardDetails=False)
    return cache["describe_clusters"]

@registry.register_check("memorydb")
def memorydb_cluster_tls_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.1] MemoryDB Clusters should configured to use encryption in transit"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache=cache)["Clusters"]:
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])

        print(str(c["TLSEnabled"]))

        # This is a failing check
        if str(c["TLSEnabled"]) != "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-tls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
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
                "Title": "[MemoryDB.1] MemoryDB Clusters should configured to use encryption in transit",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is not configured to use Encryption in Transit with TLS. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To help keep your data secure, MemoryDB for Redis and Amazon EC2 provide mechanisms to guard against unauthorized access of your data on the server. By providing in-transit encryption capability, MemoryDB gives you a tool you can use to help protect your data when it is moving from one location to another. To configure this see the In-transit encryption (TLS) in MemoryDB section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/in-transit-encryption.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName
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
                        "ISO 27001:2013 A.14.1.3",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-tls-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
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
                "Title": "[MemoryDB.1] MemoryDB Clusters should configured to use encryption in transit",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is configured to use Encryption in Transit with TLS.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To help keep your data secure, MemoryDB for Redis and Amazon EC2 provide mechanisms to guard against unauthorized access of your data on the server. By providing in-transit encryption capability, MemoryDB gives you a tool you can use to help protect your data when it is moving from one location to another. To configure this see the In-transit encryption (TLS) in MemoryDB section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/in-transit-encryption.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName
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
                        "ISO 27001:2013 A.14.1.3",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("memorydb")
def memorydb_cluster_kms_cmk_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.2] MemoryDB Clusters should used KMS CMKs for encryption at rest"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache=cache)["Clusters"]:
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])

        try:
            kmsKeyId = str(c["KmsKeyId"])
        except Exception:
            kmsKeyId = 'NO_KMS_CMK'

        # This is a failing check
        if kmsKeyId == "NO_KMS_CMK":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-kms-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[MemoryDB.2] MemoryDB Clusters should used KMS CMKs for encryption at rest",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is not configured to use a KMS CMK for Encryption at Rest. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To help keep your data secure, MemoryDB for Redis and Amazon S3 provide different ways to restrict access to data in your clusters. MemoryDB supports symmetric customer managed root keys (KMS key) for encryption at rest. Customer-managed KMS keys are encryption keys that you create, own and manage in your AWS account. To configure this see the At-Rest Encryption in MemoryDB section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName,
                                "KmsKeyId": kmsKeyId
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
                        "ISO 27001:2013 A.8.2.3",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-kms-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
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
                "Title": "[MemoryDB.2] MemoryDB Clusters should used KMS CMKs for encryption at rest",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is configured to use a KMS CMK for Encryption at Rest.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To help keep your data secure, MemoryDB for Redis and Amazon S3 provide different ways to restrict access to data in your clusters. MemoryDB supports symmetric customer managed root keys (KMS key) for encryption at rest. Customer-managed KMS keys are encryption keys that you create, own and manage in your AWS account. To configure this see the At-Rest Encryption in MemoryDB section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName,
                                "KmsKeyId": kmsKeyId
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
                        "ISO 27001:2013 A.8.2.3",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("memorydb")
def memorydb_auto_minor_version_update_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.3] MemoryDB Clusters should be configured to conduct automatic minor version updates"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache=cache)["Clusters"]:
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])

        memDbAutoMinorUpd = str(c["AutoMinorVersionUpgrade"])
        # This is a failing check
        if memDbAutoMinorUpd != "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-auto-minor-version-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MemoryDB.3] MemoryDB Clusters should be configured to conduct automatic minor version updates",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is not configured to conduct automatic minor version updates. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "MemoryDB by default automatically manages the patch version of your running clusters through service updates. You can additionally opt out from auto minor version upgrade if you set the AutoMinorVersionUpgrade property of your clusters to false. However, you can not opt out from auto patch version upgrade.. To configure this see the Engine versions and upgrading section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/engine-versions.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-auto-minor-version-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MemoryDB.3] MemoryDB Clusters should be configured to conduct automatic minor version updates",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is configured to conduct automatic minor version updates.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "MemoryDB by default automatically manages the patch version of your running clusters through service updates. You can additionally opt out from auto minor version upgrade if you set the AutoMinorVersionUpgrade property of your clusters to false. However, you can not opt out from auto patch version upgrade.. To configure this see the Engine versions and upgrading section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/engine-versions.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsMemoryDBCluster",
                        "Id": memDbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": memDbName,
                                "Status": memDbStatus,
                                "NodeType": memDbNodeType,
                                "EngineVersion": memDbEngineVersion,
                                "ParameterGroupName": memDbPgName,
                                "SubnetGroupName": memDbSnetGrpName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding