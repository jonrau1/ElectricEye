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

def describe_clusters(cache, session):
    memorydb = session.client("memorydb")
    response = cache.get("describe_clusters")
    if response:
        return response
    cache["describe_clusters"] = memorydb.describe_clusters(MaxResults=100,ShowShardDetails=False)
    return cache["describe_clusters"]

@registry.register_check("memory-db")
def memorydb_cluster_tls_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.1] MemoryDB Clusters should configured to use encryption in transit"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])

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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("memory-db")
def memorydb_cluster_kms_cmk_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.2] MemoryDB Clusters should used KMS CMKs for encryption at rest"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("memory-db")
def memorydb_auto_minor_version_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.3] MemoryDB Clusters should be configured to conduct automatic minor version updates"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
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
                        "Text": "MemoryDB by default automatically manages the patch version of your running clusters through service updates. You can additionally opt out from auto minor version upgrade if you set the AutoMinorVersionUpgrade property of your clusters to false. However, you can not opt out from auto patch version upgrade. To configure this see the Engine versions and upgrading section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/engine-versions.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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
                        "Text": "MemoryDB by default automatically manages the patch version of your running clusters through service updates. You can additionally opt out from auto minor version upgrade if you set the AutoMinorVersionUpgrade property of your clusters to false. However, you can not opt out from auto patch version upgrade. To configure this see the Engine versions and upgrading section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/engine-versions.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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

@registry.register_check("memory-db")
def memorydb_sns_notification_tracking_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.4] MemoryDB Clusters should be actively monitored with SNS"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])

        try:
            snsMonitoring = str(c["SnsTopicArn"])
        except Exception:
            snsMonitoring = "False"
        # This is a failing check
        if snsMonitoring == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": memDbArn + "/memorydb-cluster-sns-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MemoryDB.4] MemoryDB Clusters should be actively monitored with SNS",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is not configured to be monitored for Event Notifications with Amazon SNS. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "MemoryDB can publish messages using Amazon Simple Notification Service (SNS) when significant events happen on a cluster. This feature can be used to refresh the server-lists on client machines connected to individual node endpoints of a cluster. To configure this see the Event Notifications and Amazon SNS section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/memorydbsns.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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
                "Id": memDbArn + "/memorydb-cluster-sns-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": memDbArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[MemoryDB.4] MemoryDB Clusters should be actively monitored with SNS",
                "Description": "MemoryDB Cluster "
                + memDbName
                + " is configured to be monitored for Event Notifications with Amazon SNS. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "MemoryDB can publish messages using Amazon Simple Notification Service (SNS) when significant events happen on a cluster. This feature can be used to refresh the server-lists on client machines connected to individual node endpoints of a cluster. To configure this see the Event Notifications and Amazon SNS section in the Amazon MemoryDB Developer Guide for more information.",
                        "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/memorydbsns.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "AWS MemoryDB for Redis",
                    "AssetComponent": "Database Cluster"
                },
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
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
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

@registry.register_check("memory-db")
def memorydb_user_admin_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.5] MemoryDB Cluster Users with administrative privileges should be validated"""
    memorydb = session.client("memorydb")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])
        # Parse ACL, check the ACLs for Users to associate to the Cluster and evaluate the User's ACL Access String
        aclName = str(c['ACLName'])
        for acl in memorydb.describe_acls(ACLName=aclName,MaxResults=50)['ACLs']:
            for user in acl['UserNames']:
                userData = memorydb.describe_users(UserName=user)['Users'][0]
                userAccessString = str(userData["AccessString"])
                userArn = str(userData["ARN"])
                userName = str(userData["Name"])

                # This is a failing check - "on ~* &* +@all" means the user can have access to everything
                if userAccessString == "on ~* &* +@all":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": memDbArn + "-" + userArn + "/memorydb-user-admin-validation-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": memDbArn + "-" + userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[MemoryDB.5] MemoryDB Cluster Users with administrative privileges should be validated",
                        "Description": "MemoryDB User "
                        + userName
                        + " for MemoryDB Cluster "
                        + memDbName
                        + " currently has full admin privileges via ACL Access String of 'on ~* &* +@all' and should be reviewed. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "Access control lists (ACLs) are designed as a way to organize access to clusters. With ACLs, you create users and assign them specific permissions by using an access string, as described following. You assign the users to Access control lists aligned with a specific role that are then deployed to one or more MemoryDB clusters. To configure this see the Authenticating users with Access Control Lists (ACLs) section in the Amazon MemoryDB Developer Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/clusters.acls.html#access-string"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS MemoryDB for Redis",
                            "AssetComponent": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMemoryDBClusterUser",
                                "Id": userArn,
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
                                        "ACLName": aclName,
                                        "UserName": userName
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
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": memDbArn + "-" + userArn + "/memorydb-user-admin-validation-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": memDbArn + "-" + userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 75,
                        "Title": "[MemoryDB.5] MemoryDB Cluster Users with administrative privileges should be validated",
                        "Description": "MemoryDB User "
                        + userName
                        + " for MemoryDB Cluster "
                        + memDbName
                        + " does not have full admin privileges via ACL Access String of 'on ~* &* +@all', but should still be reviewed for existing permissions. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "Access control lists (ACLs) are designed as a way to organize access to clusters. With ACLs, you create users and assign them specific permissions by using an access string, as described following. You assign the users to Access control lists aligned with a specific role that are then deployed to one or more MemoryDB clusters. To configure this see the Authenticating users with Access Control Lists (ACLs) section in the Amazon MemoryDB Developer Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/clusters.acls.html#access-string"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS MemoryDB for Redis",
                            "AssetComponent": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMemoryDBClusterUser",
                                "Id": userArn,
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
                                        "ACLName": aclName,
                                        "UserName": userName
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
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding

@registry.register_check("memory-db")
def memorydb_user_password_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MemoryDB.6] MemoryDB Cluster Users should require additional password authentication"""
    memorydb = session.client("memorydb")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for c in describe_clusters(cache, session)["Clusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(c,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Gather basic information
        memDbArn = str(c["ARN"])
        memDbName = str(c["Name"])
        memDbStatus = str(c["Status"])
        memDbNodeType = str(c["NodeType"])
        memDbEngineVersion = str(c["EngineVersion"])
        memDbPgName = str(c["ParameterGroupName"])
        memDbSnetGrpName = str(c["SubnetGroupName"])
        # Parse ACL, check the ACLs for Users to associate to the Cluster and evaluate the User's ACL Access String
        aclName = str(c['ACLName'])
        for acl in memorydb.describe_acls(ACLName=aclName,MaxResults=50)['ACLs']:
            for user in acl['UserNames']:
                userData = memorydb.describe_users(UserName=user)['Users'][0]
                userPwPolicy = str(userData["Authentication"]["Type"])
                userArn = str(userData["ARN"])
                userName = str(userData["Name"])

                # This is a failing check
                if userPwPolicy == "no-password":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": userArn + "/memorydb-user-password-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": memDbArn + "-" + userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[MemoryDB.6] MemoryDB Cluster Users should require additional password authentication",
                        "Description": "MemoryDB User "
                        + userName
                        + " for MemoryDB Cluster "
                        + memDbName
                        + " does not currently require a password when authenticating to MemoryDB. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "The user information for ACLs users is a user name, and optionally a password and an access string. The access string provides the permission level on keys and commands. The name is unique to the user and is what is passed to the engine. When creating a user, you can set up to two passwords. When you modify a password, any existing connections to clusters are maintained. To configure this see the Authenticating users with Access Control Lists (ACLs) section in the Amazon MemoryDB Developer Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/clusters.acls.html#rbac-using"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS MemoryDB for Redis",
                            "AssetComponent": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMemoryDBClusterUser",
                                "Id": userArn,
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
                                        "ACLName": aclName,
                                        "UserName": userName
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
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": userArn + "/memorydb-user-password-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": memDbArn + "-" + userArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[MemoryDB.6] MemoryDB Cluster Users should require additional password authentication",
                        "Description": "MemoryDB User "
                        + userName
                        + " for MemoryDB Cluster "
                        + memDbName
                        + " does not currently require a password when authenticating to MemoryDB. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "The user information for ACLs users is a user name, and optionally a password and an access string. The access string provides the permission level on keys and commands. The name is unique to the user and is what is passed to the engine. When creating a user, you can set up to two passwords. When you modify a password, any existing connections to clusters are maintained. To configure this see the Authenticating users with Access Control Lists (ACLs) section in the Amazon MemoryDB Developer Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/memorydb/latest/devguide/clusters.acls.html#rbac-using"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Identity & Access Management",
                            "AssetService": "AWS MemoryDB for Redis",
                            "AssetComponent": "User"
                        },
                        "Resources": [
                            {
                                "Type": "AwsMemoryDBClusterUser",
                                "Id": userArn,
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
                                        "ACLName": aclName,
                                        "UserName": userName
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
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding