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
rds = boto3.client("rds")
ec2 = boto3.client("ec2")

# loop through all RDS DB instances
def describe_db_instances(cache):
    response = cache.get("describe_db_instances")
    if response:
        return response
    cache["describe_db_instances"] = rds.describe_db_instances(
        Filters=[
            {
                "Name": "engine",
                "Values": [
                    "aurora",
                    "aurora-mysql",
                    "aurora-postgresql",
                    "mariadb",
                    "mysql",
                    "oracle-ee",
                    "postgres",
                    "sqlserver-ee",
                    "sqlserver-se",
                    "sqlserver-ex",
                    "sqlserver-web",
                ],
            }
        ],
        MaxRecords=100,
    )
    return cache["describe_db_instances"]

# loop through all RDS DB snapshots
def describe_db_snapshots(cache):
    response = cache.get("describe_db_snapshots")
    if response:
        return response
    cache["describe_db_snapshots"] = rds.describe_db_snapshots()
    return cache["describe_db_snapshots"]

@registry.register_check("rds")
def rds_instance_ha_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.1] RDS instances should be configured for high availability"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        highAvailabilityCheck = str(dbinstances["MultiAZ"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if highAvailabilityCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[RDS.1] RDS instances should be configured for high availability",
                "Description": "RDS DB instance "
                + instanceId
                + " is not configured for high availability. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance high availability and how to configure it refer to the High Availability (Multi-AZ) for Amazon RDS section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                            }
                        },
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
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.1] RDS instances should be configured for high availability",
                "Description": "RDS DB instance "
                + instanceId
                + " is configured for high availability.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance high availability and how to configure it refer to the High Availability (Multi-AZ) for Amazon RDS section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                            }
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("rds")
def rds_instance_public_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.2] RDS instances should not be publicly accessible"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        publicAccessibleCheck = str(dbinstances["PubliclyAccessible"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if publicAccessibleCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
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
                "Title": "[RDS.2] RDS instances should not be publicly accessible",
                "Description": "RDS DB instance "
                + instanceId
                + " is publicly accessible. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance publicly access and how to change it refer to the Hiding a DB Instance in a VPC from the Internet section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                                "PubliclyAccessible": True,
                            }
                        },
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
                "Id": instanceArn + "/instance-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
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
                "Title": "[RDS.2] RDS instances should not be publicly accessible",
                "Description": "RDS DB instance "
                + instanceId
                + " is not publicly accessible. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance publicly access and how to change it refer to the Hiding a DB Instance in a VPC from the Internet section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                                "PubliclyAccessible": False,
                            }
                        },
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

@registry.register_check("rds")
def rds_instance_storage_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.3] RDS instances should have encrypted storage"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        rdsStorageEncryptionCheck = str(dbinstances["StorageEncrypted"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if rdsStorageEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
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
                "Title": "[RDS.3] RDS instances should have encrypted storage",
                "Description": "RDS DB instance "
                + instanceId
                + " does not have encrypted storage. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS storage encryption refer to the Enabling Amazon RDS Encryption for a DB Instance section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                                "StorageEncrypted": False,
                            }
                        },
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
                "Id": instanceArn + "/instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
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
                "Title": "[RDS.3] RDS instances should have encrypted storage",
                "Description": "RDS DB instance " + instanceId + " has encrypted storage.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS storage encryption refer to the Enabling Amazon RDS Encryption for a DB Instance section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                                "StorageEncrypted": True
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
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("rds")
def rds_instance_iam_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.4] RDS instances that support IAM Authentication should use IAM Authentication"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        iamDbAuthCheck = str(dbinstances["IAMDatabaseAuthenticationEnabled"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if instanceEngine == "mysql" or "postgres":
            if iamDbAuthCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/instance-iam-auth-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[RDS.4] RDS instances that support IAM Authentication should use IAM Authentication",
                    "Description": "RDS DB instance "
                    + instanceId
                    + " does not support IAM Authentication. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on RDS IAM Database Authentication and how to configure it refer to the IAM Database Authentication for MySQL and PostgreSQL section of the Amazon Relational Database Service User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": instanceId,
                                    "DBInstanceClass": instanceClass,
                                    "DbInstancePort": instancePort,
                                    "Engine": instanceEngine,
                                    "EngineVersion": instanceEngineVersion,
                                    "IAMDatabaseAuthenticationEnabled": False,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/instance-iam-auth-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[RDS.4] RDS instances that support IAM Authentication should use IAM Authentication",
                    "Description": "RDS DB instance "
                    + instanceId
                    + " supports IAM Authentication.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on RDS IAM Database Authentication and how to configure it refer to the IAM Database Authentication for MySQL and PostgreSQL section of the Amazon Relational Database Service User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": instanceId,
                                    "DBInstanceClass": instanceClass,
                                    "DbInstancePort": instancePort,
                                    "Engine": instanceEngine,
                                    "EngineVersion": instanceEngineVersion,
                                    "IAMDatabaseAuthenticationEnabled": True,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        else:
            pass

@registry.register_check("rds")
def rds_instance_domain_join_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.5] RDS instances that support Kerberos Authentication should be joined to a domain"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        activeDirectoryDomainCheck = str(dbinstances["DomainMemberships"])
        if (
            instanceEngine == "mysql"
            or "oracle-ee"
            or "oracle-se1"
            or "oracle-se2"
            or "oracle-se"
            or "postgres"
            or "sqlserver-ee"
            or "sqlserver-se"
            or "sqlserver-ex"
            or "sqlserver-web"
        ):
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if activeDirectoryDomainCheck == "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/instance-domain-join-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[RDS.5] RDS instances that support Kerberos Authentication should be joined to a domain",
                    "Description": "RDS DB instance "
                    + instanceId
                    + " is not joined to a domain, and likely does not support Kerberos Authentication because of it. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on RDS instances that support Kerberos Authentication and how to configure it refer to the Kerberos Authentication section of the Amazon Relational Database Service User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/kerberos-authentication.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": instanceId,
                                    "DBInstanceClass": instanceClass,
                                    "DbInstancePort": instancePort,
                                    "Engine": instanceEngine,
                                    "EngineVersion": instanceEngineVersion,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/instance-domain-join-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[RDS.5] RDS instances that support Kerberos Authentication should be joined to a domain",
                    "Description": "RDS DB instance "
                    + instanceId
                    + " is joined to a domain, and likely supports Kerberos Authentication because of it.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on RDS instances that support Kerberos Authentication and how to configure it refer to the Kerberos Authentication section of the Amazon Relational Database Service User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/kerberos-authentication.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsRdsDbInstance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsRdsDbInstance": {
                                    "DBInstanceIdentifier": instanceId,
                                    "DBInstanceClass": instanceClass,
                                    "DbInstancePort": instancePort,
                                    "Engine": instanceEngine,
                                    "EngineVersion": instanceEngineVersion,
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-6",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 AC-3",
                            "NIST SP 800-53 AC-16",
                            "NIST SP 800-53 AC-19",
                            "NIST SP 800-53 AC-24",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 PE-2",
                            "NIST SP 800-53 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        else:
            pass

@registry.register_check("rds")
def rds_instance_performance_insights_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.6] RDS instances should have performance insights enabled"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        perfInsightsCheck = str(dbinstances["PerformanceInsightsEnabled"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if perfInsightsCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-perf-insights-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[RDS.6] RDS instances should have performance insights enabled",
                "Description": "RDS DB instance "
                + instanceId
                + " does not have performance insights enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS performance insights and how to configure it refer to the Using Amazon RDS Performance Insights section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-perf-insights-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.6] RDS instances should have performance insights enabled",
                "Description": "RDS DB instance "
                + instanceId
                + " has performance insights enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS performance insights and how to configure it refer to the Using Amazon RDS Performance Insights section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
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

@registry.register_check("rds")
def rds_instance_deletion_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.7] RDS instances should have deletion protection enabled"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        deletionProtectionCheck = str(dbinstances["DeletionProtection"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if deletionProtectionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-deletion-prot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[RDS.7] RDS instances should have deletion protection enabled",
                "Description": "RDS DB instance "
                + instanceId
                + " does not have deletion protection enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS deletion protection and how to configure it refer to the Deletion Protection section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "DeletionProtection": False,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                            }
                        },
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
                "Id": instanceArn + "/instance-database-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.7] RDS instances should have deletion protection enabled",
                "Description": "RDS DB instance "
                + instanceId
                + " has deletion protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS deletion protection and how to configure it refer to the Deletion Protection section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "DeletionProtection": False,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
                            }
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("rds")
def rds_instance_cloudwatch_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.8] RDS instances should publish database logs to CloudWatch Logs"""
    response = describe_db_instances(cache)
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            logCheck = str(dbinstances["EnabledCloudwatchLogsExports"])
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-database-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.8] RDS instances should publish database logs to CloudWatch Logs",
                "Description": "RDS DB instance "
                + instanceId
                + " publishes "
                + logCheck
                + " logs to CloudWatch Logs. Review the types of logs that are published to ensure they fulfill organizational and regulatory requirements as needed.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on database logging with CloudWatch and how to configure it refer to the Publishing Database Logs to Amazon CloudWatch Logs section of the Amazon Relational Database Service User Guide. Aurora does support this but you will need to address another User Guide for information on Aurora database logging with CloudWatch",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html#USER_LogAccess.Procedural.UploadtoCloudWatch",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-deletion-prot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[RDS.8] RDS instances should publish database logs to CloudWatch Logs",
                "Description": "RDS DB instance "
                + instanceId
                + " does not publish database logs to CloudWatch Logs. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on database logging with CloudWatch and how to configure it refer to the Publishing Database Logs to Amazon CloudWatch Logs section of the Amazon Relational Database Service User Guide. Aurora does support this but you will need to address another User Guide for information on Aurora database logging with CloudWatch",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html#USER_LogAccess.Procedural.UploadtoCloudWatch",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion,
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("rds")
def rds_snapshot_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.9] RDS snapshots should be encrypted"""
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for snapshot in myRdsSnapshots:
        snapshotId = str(snapshot["DBSnapshotIdentifier"])
        snapshotArn = str(snapshot["DBSnapshotArn"])
        snapshotEncryptionCheck = str(snapshot["Encrypted"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if snapshotEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": snapshotArn + "/rds-snapshot-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snapshotArn,
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
                "Title": "[RDS.9] RDS snapshots should be encrypted",
                "Description": "RDS snapshot "
                + snapshotId
                + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on encrypting RDS snapshots refer to the AWS Premium Support Knowledge Center Entry How do I encrypt Amazon RDS snapshots?",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/encrypt-rds-snapshots/",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbSnapshot",
                        "Id": snapshotArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"SnapshotId": snapshotId}},
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
                "Id": snapshotArn + "/rds-snapshot-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snapshotArn,
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
                "Title": "[RDS.9] RDS snapshots should be encrypted",
                "Description": "RDS snapshot " + snapshotId + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on encrypting RDS snapshots refer to the AWS Premium Support Knowledge Center Entry How do I encrypt Amazon RDS snapshots?",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/encrypt-rds-snapshots/"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbSnapshot",
                        "Id": snapshotArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"SnapshotId": snapshotId}},
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("rds")
def rds_snapshot_public_share_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.10] RDS snapshots should not be publicly shared"""
    response = describe_db_snapshots(cache)
    myRdsSnapshots = response["DBSnapshots"]
    for snapshot in myRdsSnapshots:
        snapshotId = str(snapshot["DBSnapshotIdentifier"])
        snapshotArn = str(snapshot["DBSnapshotArn"])
        response = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshotId)
        rdsSnapshotAttrs = response["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
        for attribute in rdsSnapshotAttrs:
            attrName = str(attribute["AttributeName"])
            if attrName == "restore":
                attrValue = str(attribute["AttributeValues"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if attrValue == "['all']":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": snapshotArn + "/rds-snapshot-public-share-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": snapshotArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[RDS.10] RDS snapshots should not be publicly shared",
                        "Description": "RDS snapshot "
                        + snapshotId
                        + " is publicly shared. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on sharing RDS snapshots refer to the Sharing a Snapshot section of the Amazon Relational Database Service User Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html#USER_ShareSnapshot.Sharing",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsRdsDbSnapshot",
                                "Id": snapshotArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"SnapshotId": snapshotId}},
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": snapshotArn + "/rds-snapshot-public-share-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": snapshotArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[RDS.10] RDS snapshots should not be publicly shared",
                        "Description": "RDS snapshot " + snapshotId + " is not publicly shared.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on sharing RDS snapshots refer to the Sharing a Snapshot section of the Amazon Relational Database Service User Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html#USER_ShareSnapshot.Sharing",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsRdsDbSnapshot",
                                "Id": snapshotArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"SnapshotId": snapshotId}},
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
            else:
                print("non-supported attribute encountered")
                continue

@registry.register_check("rds")
def rds_aurora_cluster_activity_streams_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.11] RDS Aurora Clusters should use Database Activity Streams"""
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Loop through clusters npow
    for dbc in rds.describe_db_clusters(MaxRecords=100)["DBClusters"]:
        ddcArn = str(dbc["DBClusterArn"])
        dbcId = str(dbc["DBClusterIdentifier"])
        allocStorage = int(dbc["AllocatedStorage"])
        dbSubnet = str(dbc["DBSubnetGroup"])
        endpt = str(dbc["Endpoint"])
        engine = str(dbc["Engine"])
        engineVer = str(dbc["EngineVersion"])
        astreamStat = str(dbc["ActivityStreamStatus"])

        # This is a failing finding
        if astreamStat != "started" or "starting":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": ddcArn + "/rds-aurora-cluster-activity-streams-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ddcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[RDS.11] RDS Aurora Clusters should use Database Activity Streams",
                "Description": "RDS Aurora Cluster "
                + dbcId
                + " is not using Database Activity Streams. Database Activity Streams allow you to get real-time insights into security and operational behaviors in your DB Cluster so that you can interdict potentially malicious activity. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Database Activity Streams refer to the Using Database Activity Streams with Amazon Aurora section of the Amazon Aurora User Guide for Aurora (yes it's called that)",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbCluster",
                        "Id": ddcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "AwsRdsDbCluster": {
                            "ActivityStreamStatus": astreamStat,
                            "AllocatedStorage": allocStorage,
                            "DbClusterIdentifier": dbcId,
                            "DbSubnetGroup": dbSubnet,
                            "Endpoint": endpt,
                            "Engine": engine,
                            "EngineVersion": engineVer
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
                        "ISO 27001:2013 A.16.1.7",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": ddcArn + "/rds-aurora-cluster-activity-streams-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ddcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.11] RDS Aurora Clusters should use Database Activity Streams",
                "Description": "RDS Aurora Cluster "
                + dbcId
                + " is using Database Activity Streams.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Database Activity Streams refer to the Using Database Activity Streams with Amazon Aurora section of the Amazon Aurora User Guide for Aurora (yes it's called that)",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbCluster",
                        "Id": ddcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "AwsRdsDbCluster": {
                            "ActivityStreamStatus": astreamStat,
                            "AllocatedStorage": allocStorage,
                            "DbClusterIdentifier": dbcId,
                            "DbSubnetGroup": dbSubnet,
                            "Endpoint": endpt,
                            "Engine": engine,
                            "EngineVersion": engineVer
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
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("rds")
def rds_aurora_cluster_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.12] RDS Aurora Clusters should be encrypted"""
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Loop through clusters npow
    for dbc in rds.describe_db_clusters(MaxRecords=100)["DBClusters"]:
        ddcArn = str(dbc["DBClusterArn"])
        dbcId = str(dbc["DBClusterIdentifier"])
        allocStorage = int(dbc["AllocatedStorage"])
        dbSubnet = str(dbc["DBSubnetGroup"])
        endpt = str(dbc["Endpoint"])
        engine = str(dbc["Engine"])
        engineVer = str(dbc["EngineVersion"])

        # This is a failing finding
        if str(dbc["StorageEncrypted"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": ddcArn + "/rds-aurora-cluster-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ddcArn,
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
                "Title": "[RDS.12] RDS Aurora Clusters should be encrypted",
                "Description": "RDS Aurora Cluster "
                + dbcId
                + " is not using Database Activity Streams. Database Activity Streams allow you to get real-time insights into security and operational behaviors in your DB Cluster so that you can interdict potentially malicious activity. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Database Activity Streams refer to the Using Database Activity Streams with Amazon Aurora section of the Amazon Aurora User Guide for Aurora (yes it's called that)",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbCluster",
                        "Id": ddcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "AwsRdsDbCluster": {
                            "AllocatedStorage": allocStorage,
                            "DbClusterIdentifier": dbcId,
                            "DbSubnetGroup": dbSubnet,
                            "Endpoint": endpt,
                            "Engine": engine,
                            "EngineVersion": engineVer
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
                "Id": ddcArn + "/rds-aurora-cluster-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": ddcArn,
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
                "Title": "[RDS.12] RDS Aurora Clusters should be encrypted",
                "Description": "RDS Aurora Cluster "
                + dbcId
                + " is not using Database Activity Streams. Database Activity Streams allow you to get real-time insights into security and operational behaviors in your DB Cluster so that you can interdict potentially malicious activity. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Database Activity Streams refer to the Using Database Activity Streams with Amazon Aurora section of the Amazon Aurora User Guide for Aurora (yes it's called that)",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbCluster",
                        "Id": ddcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "AwsRdsDbCluster": {
                            "AllocatedStorage": allocStorage,
                            "DbClusterIdentifier": dbcId,
                            "DbSubnetGroup": dbSubnet,
                            "Endpoint": endpt,
                            "Engine": engine,
                            "EngineVersion": engineVer
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

@registry.register_check("rds")
def rds_instance_snapshot_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.13] RDS instances should be have snapshots"""
    response = describe_db_instances(cache)
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        # evaluate snapshots
        snapshots = rds.describe_db_snapshots(DBInstanceIdentifier=instanceId)
        # this is a passing check, we're just interested in the existance of Snapshots, not their configuration (other checks do it)
        if snapshots["DBSnapshots"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-snapshot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[RDS.13] RDS instances should be have snapshots",
                "Description": "RDS DB instance "
                + instanceId
                + " has at least one snapshot.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance resilience and snapshotting or recovery refer to the Resilience in Amazon RDS section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/disaster-recovery-resiliency.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion
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
                        "ISO 27001:2013 A.17.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/instance-snapshot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[RDS.13] RDS instances should be have snapshots",
                "Description": "RDS DB instance "
                + instanceId
                + " does not have a snapshot which can reduce cyber resilience due to a lack of a viable backup. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on RDS instance resilience and snapshotting or recovery refer to the Resilience in Amazon RDS section of the Amazon Relational Database Service User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/disaster-recovery-resiliency.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": instanceId,
                                "DBInstanceClass": instanceClass,
                                "DbInstancePort": instancePort,
                                "Engine": instanceEngine,
                                "EngineVersion": instanceEngineVersion
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
                        "ISO 27001:2013 A.17.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("rds")
def rds_instance_secgroup_risk_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.14] RDS instance security groups should not allow public access to DB ports"""
    response = describe_db_instances(cache)
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    myRdsInstances = response["DBInstances"]
    response = describe_db_snapshots(cache)
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        # details for SG comparison
        endpointPort = str(dbinstances["Endpoint"]["Port"])
        # loop list of SGs
        for dbsg in dbinstances["VpcSecurityGroups"]:
            sgId = dbsg["VpcSecurityGroupId"]
            # lookup in EC2
            for sgr in ec2.describe_security_group_rules(Filters=[{'Name': 'group-id','Values': [sgId]}])["SecurityGroupRules"]:
                # pull out specific SG rules
                if str(sgr["IsEgress"]) == 'True':
                    continue
                else:
                    # grab port numbers for comparisons
                    toPort = str(sgr["ToPort"])
                    fromPort = str(sgr["FromPort"])
                    # handle the fact that there may not be inbound IPv4/6 rules
                    try:
                        ipV4Cidr = str(sgr["CidrIpv4"])
                    except KeyError:
                        ipV4Cidr = "NoCidrHereBoss"
                    try:
                        ipV6Cidr = str(sgr["CidrIpv6"])
                    except KeyError:
                        ipV6Cidr = "NoCidrHereBoss"
                    # Rule evaluation time - check if ports match DB ports
                    if (toPort or fromPort == endpointPort):
                        # keep going we found a SG rule that matches DB port
                        if (ipV4Cidr == "0.0.0.0/0" or ipV6Cidr == "::/0"):
                            # open access found - this is a failing finding
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": instanceArn + "/db-sg-risk-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": instanceArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "HIGH"},
                                "Confidence": 99,
                                "Title": "[RDS.14] RDS instance security groups should not allow public access to DB ports",
                                "Description": "RDS DB instance "
                                + instanceId
                                + " allows open access to DB ports via the Security Group which can allow for lateral movement and data exfiltration. Refer to the remediation instructions if this configuration is not intended.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on RDS network security refer to the Controlling access with security groups section of the Amazon Relational Database Service User Guide",
                                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsRdsDbInstance",
                                        "Id": instanceArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsRdsDbInstance": {
                                                "DBInstanceIdentifier": instanceId,
                                                "DBInstanceClass": instanceClass,
                                                "DbInstancePort": instancePort,
                                                "Engine": instanceEngine,
                                                "EngineVersion": instanceEngineVersion
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
                        else:
                            # this is a passing finding
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": instanceArn + "/db-sg-risk-check",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": instanceArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": "[RDS.14] RDS instance security groups should not allow public access to DB ports",
                                "Description": "RDS DB instance "
                                + instanceId
                                + " does not allow open access to DB ports via the Security Group.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on RDS network security refer to the Controlling access with security groups section of the Amazon Relational Database Service User Guide",
                                        "Url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsRdsDbInstance",
                                        "Id": instanceArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsRdsDbInstance": {
                                                "DBInstanceIdentifier": instanceId,
                                                "DBInstanceClass": instanceClass,
                                                "DbInstancePort": instancePort,
                                                "Engine": instanceEngine,
                                                "EngineVersion": instanceEngineVersion
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
                                        "ISO 27001:2013 A.13.2.1"
                                    ]
                                },
                                "Workflow": {"Status": "RESOLVED"},
                                "RecordState": "ARCHIVED"
                            }
                            yield finding
                    else:
                        continue

@registry.register_check("rds")
def rds_instance_instance_alerting_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.15] RDS instances should be monitored for important events using Event Subscriptions"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Determine if there are any alerts at all via list comprehension - fail if empty
    # To avoid writing out 8 variations of this logic - ignoring if an Event is disabled or not...
    if rds.describe_event_subscriptions()["EventSubscriptionsList"]:
        for events in rds.describe_event_subscriptions()["EventSubscriptionsList"]:
            # Ignore non-Instance events
            if str(events["SourceType"]) != "db-instance":
                continue
            # If the field `EventCategoriesList` does not exist it means all events are being logged and passes
            try:
                # attempt to find matches within the Event Category List
                eventList = events["EventCategoriesList"]
                # all 3 Event types within list of strings must be in `eventList` variable - returns true, so this is a passing check
                if all(x in ["maintenance", "configuration change", "failure"] for x in eventList):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{awsAccountId}:{awsRegion}",
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[RDS.15] RDS instances should be monitored for important events using Event Subscriptions",
                        "Description": f"AWS Account {awsAccountId} in Region {awsRegion} has an Event Subscription to alert on critical security and performance events for RDS which include 'maintenance', 'configuration change', and 'failure'.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-instance-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-instance --event-categories "maintenance" "configuration change" "failure" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                                "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsAccount",
                                "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                                "Partition": awsPartition,
                                "Region": awsRegion
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{awsAccountId}:{awsRegion}",
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[RDS.15] RDS instances should be monitored for important events using Event Subscriptions",
                        "Description": f"AWS Account {awsAccountId} in Region {awsRegion} does not have an Event Subscription to alert on critical security and performance events for RDS which include 'maintenance', 'configuration change', and 'failure'. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-instance-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-instance --event-categories "maintenance" "configuration change" "failure" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                                "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsAccount",
                                "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                                "Partition": awsPartition,
                                "Region": awsRegion
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
            # this is a passing check - if the value doesn't exist it means all possible checks are supported
            except KeyError:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{awsAccountId}:{awsRegion}",
                    "AwsAccountId": awsAccountId,
                    "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[RDS.15] RDS instances should be monitored for important events using Event Subscriptions",
                    "Description": f"AWS Account {awsAccountId} in Region {awsRegion} has an Event Subscription to alert on critical security and performance events for RDS which include 'maintenance', 'configuration change', and 'failure'.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-instance-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-instance --event-categories "maintenance" "configuration change" "failure" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                            "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": awsPartition,
                            "Region": awsRegion
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
    # this is a failing check due to missing alerting events
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}:{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[RDS.15] RDS instances should be monitored for important events using Event Subscriptions",
            "Description": f"AWS Account {awsAccountId} in Region {awsRegion} does not have an Event Subscription to alert on critical security and performance events for RDS which include 'maintenance', 'configuration change', and 'failure'. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-instance-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-instance --event-categories "maintenance" "configuration change" "failure" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": awsPartition,
                    "Region": awsRegion
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

@registry.register_check("rds")
def rds_instance_parameter_group_alerting_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[RDS.16] RDS parameter groups should be monitored for important events using Event Subscriptions"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Determine if there are any alerts at all via list comprehension - fail if empty
    # To avoid writing out 8 variations of this logic - ignoring if an Event is disabled or not...
    if rds.describe_event_subscriptions()["EventSubscriptionsList"]:
        for events in rds.describe_event_subscriptions()["EventSubscriptionsList"]:
            # Ignore non-Instance events
            if str(events["SourceType"]) != "db-parameter-group":
                continue
            # If the field `EventCategoriesList` does not exist it means all events are being logged and passes
            try:
                # attempt to find matches within the Event Category List
                eventList = events["EventCategoriesList"]
                # all 3 Event types within list of strings must be in `eventList` variable - returns true, so this is a passing check
                if all(x in ["maintenance", "configuration change", "failure"] for x in eventList):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{awsAccountId}:{awsRegion}",
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[RDS.16] RDS parameter groups should be monitored for important events using Event Subscriptions",
                        "Description": f"AWS Account {awsAccountId} in Region {awsRegion} has an Event Subscription to alert on critical security and performance events for RDS parameter groups which includes 'configuration change'.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-pg-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-parameter-group --event-categories "configuration change" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                                "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-21"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsAccount",
                                "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                                "Partition": awsPartition,
                                "Region": awsRegion
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": f"{awsAccountId}:{awsRegion}",
                        "AwsAccountId": awsAccountId,
                        "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[RDS.16] RDS parameter groups should be monitored for important events using Event Subscriptions",
                        "Description": f"AWS Account {awsAccountId} in Region {awsRegion} does not have an Event Subscription to alert on critical security and performance events for RDS parameter groups which includes 'configuration change'. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-pg-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-parameter-group --event-categories "configuration change" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                                "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsAccount",
                                "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                                "Partition": awsPartition,
                                "Region": awsRegion
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
            # this is a passing check - if the value doesn't exist it means all possible checks are supported
            except KeyError:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{awsAccountId}:{awsRegion}",
                    "AwsAccountId": awsAccountId,
                    "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[RDS.16] RDS parameter groups should be monitored for important events using Event Subscriptions",
                    "Description": f"AWS Account {awsAccountId} in Region {awsRegion} has an Event Subscription to alert on critical security and performance events for RDS parameter groups which includes 'configuration change'.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-pg-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-parameter-group --event-categories "configuration change" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                            "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": awsPartition,
                            "Region": awsRegion
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
    # this is a failing check due to missing alerting events
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}:{awsRegion}/rds-instance-event-sub-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}:{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[RDS.16] RDS parameter groups should be monitored for important events using Event Subscriptions",
            "Description": f"AWS Account {awsAccountId} in Region {awsRegion} does not have an Event Subscription to alert on critical security and performance events for RDS parameter groups which includes 'configuration change'. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": 'To create a Filter use the following AWS CLI Script: aws rds create-event-subscription --subscription-name critical-pg-alerts --sns-topic-arn $SNS_TOPIC_ARN --source-type db-parameter-group --event-categories "configuration change" --enabled. Or, refer to the AWS Security Hub Remediation Guide for RDS',
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-20"
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": awsPartition,
                    "Region": awsRegion
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