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
    neptune = session.client("neptune")
    response = cache.get("describe_db_instances")
    if response:
        return response
    cache["describe_db_instances"] = neptune.describe_db_instances(
        Filters=[{"Name": "engine", "Values": ["neptune"]}]
    )
    return cache["describe_db_instances"]

def describe_db_clusters(cache, session):
    neptune = session.client("neptune")
    response = cache.get("describe_db_clusters")
    if response:
        return response
    cache["describe_db_clusters"] = neptune.describe_db_clusters(
        Filters=[{"Name": "engine", "Values": ["neptune"]}]
    )
    return cache["describe_db_clusters"]

def describe_db_cluster_parameter_groups(cache, session):
    neptune = session.client("neptune")
    response = cache.get("describe_db_cluster_parameter_groups")
    if response:
        return response
    cache["describe_db_cluster_parameter_groups"] = neptune.describe_db_cluster_parameter_groups()
    return cache["describe_db_cluster_parameter_groups"]

@registry.register_check("neptune")
def neptune_instance_multi_az_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.1] Neptune database instances should be configured to be highly available"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        mutliAzCheck = str(instances["MultiAZ"])
        # this is a failing check
        if mutliAzCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Neptune.1] Neptune database instances should be configured to be highly available",
                "Description": f"Neptune database instance {neptuneDbId} does not have Multi-AZ enabled and thus is not highly available. In Neptune DB clusters, there is one primary DB instance and up to 15 Neptune replicas. The primary DB instance supports read and write operations, and performs all of the data modifications to the cluster volume. Neptune replicas connect to the same storage volume as the primary DB instance and support only read operations. Neptune replicas can offload read workloads from the primary DB instance. AWS recommends distributing the primary instance and Neptune replicas in your DB cluster over multiple Availability Zones to improve the availability of your DB cluster. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Neptune.1] Neptune database instances should be configured to be highly available",
                "Description": f"Neptune database instance {neptuneDbId} has Multi-AZ enabled and thus is highly available.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
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

@registry.register_check("neptune")
def neptune_instance_storage_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.2] Neptune database instace storage should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        storageEncryptionCheck = str(instances["StorageEncrypted"])
        # this is a failing check
        if storageEncryptionCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.2] Neptune database instace storage should be encrypted",
                "Description": f"Neptune database instance {neptuneDbId} does not have storage encryption enabled. Neptune encrypted instances provide an additional layer of data protection by helping to secure your data from unauthorized access to the underlying storage. You can use Neptune encryption to increase data protection of your applications that are deployed in the cloud. You can also use it to fulfill compliance requirements for data-at-rest encryption. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                "Id": f"{neptuneInstanceArn}/neptune-instance-storage-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.2] Neptune database instace storage should be encrypted",
                "Description": f"Neptune database instance {neptuneDbId} has storage encryption enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
                            }
                        },
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

@registry.register_check("neptune")
def neptune_instance_iam_authentication_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.3] Neptune database instaces storage should use IAM Database Authentication"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        iamDbAuthCheck = str(instances["IAMDatabaseAuthenticationEnabled"])
        # This is a failing check
        if iamDbAuthCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-iam-db-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.3] Neptune database instaces storage should use IAM Database Authentication",
                "Description": f"Neptune database instance {neptuneDbId} does not use IAM Database Authentication. AWS Identity and Access Management (IAM) is an AWS service that helps an administrator securely control access to AWS resources. IAM administrators control who can be authenticated (signed in) and authorized (have permissions) to use Neptune resources. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # This is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-iam-db-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
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
                "Title": "[Neptune.3] Neptune database instaces storage should use IAM Database Authentication",
                "Description": f"Neptune database instance {neptuneDbId} uses IAM Database Authentication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("neptune")
def neptune_cluster_parameter_ssl_enforcement_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases"""
    neptune = session.client("neptune")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for parametergroup in describe_db_cluster_parameter_groups(cache, session)["DBClusterParameterGroups"]:
        parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
        parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
        # Parse the parameters in the PG
        r = neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
        for parameters in r["Parameters"]:
            if str(parameters["ParameterName"]) == "neptune_enforce_ssl":
                sslEnforcementCheck = str(parameters["ParameterValue"])
                # this is a failing check
                if sslEnforcementCheck == "0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{parameterGroupArn}/neptune-cluster-param-group-ssl-enforcement-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases",
                        "Description": f"Neptune cluster parameter group {parameterGroupName} does not enforce SSL connections. To protect your data, AWS recommends that you always connect to Neptune endpoints through SSL, using HTTPS instead of HTTP. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneParameterGroup",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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
                        "Id": f"{parameterGroupArn}/neptune-cluster-param-group-ssl-enforcement-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.4] Neptune cluster parameter groups should enforce SSL connections to Neptune databases",
                        "Description": f"Neptune cluster parameter group {parameterGroupName} enforces SSL connections.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on enforcing SSL/HTTPS connections to Neptune instances refer to the Encryption in Transit: Connecting to Neptune Using SSL/HTTPS section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneParameterGroup",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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

'''
THIS CHECK HAS BEEN RETIRED AND A NEW [Neptune.5] has been created in its place

@registry.register_check("neptune")
def neptune_cluster_parameter_audit_log_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for parametergroup in describe_db_cluster_parameter_groups(cache, session)["DBClusterParameterGroups"]:
        parameterGroupName = str(parametergroup["DBClusterParameterGroupName"])
        parameterGroupArn = str(parametergroup["DBClusterParameterGroupArn"])
        # Parse the parameters in the PG
        r = neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=parameterGroupName)
        for parameters in r["Parameters"]:
            if str(parameters["ParameterName"]) == "neptune_enable_audit_log":
                auditLogCheck = str(parameters["ParameterValue"])
                # this is a failing check
                if auditLogCheck == "0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{parameterGroupArn}/neptune-cluster-param-group-audit-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases",
                        "Description": f"Neptune cluster parameter group {parameterGroupName} does not enforce audit logging. To audit Amazon Neptune DB cluster activity, enable the collection of audit logs by setting a DB cluster parameter. When audit logs are enabled, you can use it to log any combination of supported events. You can view or download the audit logs to review them. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneParameterGroup",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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
                # this is a passing check
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{parameterGroupArn}/neptune-cluster-param-group-audit-logging-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": parameterGroupArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.5] Neptune cluster parameter groups should enforce audit logging for Neptune databases",
                        "Description": f"Neptune cluster parameter group {parameterGroupName} enforces audit logging.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneParameterGroup",
                                "Id": parameterGroupArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ParameterGroupName": parameterGroupName}},
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
                # complete the loop
                break
            else:
                continue
'''

@registry.register_check("neptune")
def neptune_instance_audit_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.5] Neptune database instaces should send audit logs to CloudWatch"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        cwlExports = instances["EnabledCloudwatchLogsExports"]
        # this is a failing check
        if "audit" not in cwlExports:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Neptune.5] Neptune database instaces should send audit logs to CloudWatch",
                "Description": f"Neptune database instance {neptuneDbId} does not send audit logs to AWS CloudWatch. does not enforce audit logging. To audit Amazon Neptune DB cluster activity, enable the collection of audit logs by setting a DB cluster parameter. When audit logs are enabled, you can use it to log any combination of supported events. You can view or download the audit logs to review them. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-audit-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Neptune.5] Neptune database instaces should send audit logs to CloudWatch",
                "Description": f"Neptune database instance {neptuneDbId} does not send audit logs to AWS CloudWatch. does not enforce audit logging. To audit Amazon Neptune DB cluster activity, enable the collection of audit logs by setting a DB cluster parameter. When audit logs are enabled, you can use it to log any combination of supported events. You can view or download the audit logs to review them. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on audit logging for Neptune instances refer to the Enabling Neptune Audit Logs section of the Amazon Neptune User Guide.",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html#auditing-enable",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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

@registry.register_check("neptune")
def neptune_instance_deletion_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.6] Neptune database instances should be protected from deletion"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        delProtCheck = str(instances["DeletionProtection"])
        # this is a failing check
        if delProtCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Neptune.6] Neptune database instances should be protected from deletion",
                "Description": f"Neptune database instance {neptuneDbId} does not have deletion protection enabled. You can only delete DB instances that have deletion protection disabled. Neptune enforces deletion protection regardless of whether you use the console, the AWS CLI, or the APIs to delete a DB instance. Deletion protection is enabled by default when you create a production DB instance using the AWS Management Console. Deletion protection is disabled by default if you use the AWS CLI or API commands to create a DB instance. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune deletion protection refer to the Deleting a DB Instance in Amazon Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-instances-delete.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                "Id": f"{neptuneInstanceArn}/neptune-instance-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Neptune.6] Neptune database instances should be protected from deletion",
                "Description": f"Neptune database instance {neptuneDbId} has deletion protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune deletion protection refer to the Deleting a DB Instance in Amazon Neptune section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-instances-delete.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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

@registry.register_check("neptune")
def neptune_instance_minor_version_upgrade_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.7] Neptune database instances should be protected from deletion"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instances in describe_db_instances(cache, session)["DBInstances"]:
        neptuneInstanceArn = str(instances["DBInstanceArn"])
        neptuneDbId = str(instances["DBInstanceIdentifier"])
        minorVersionUpgradeCheck = str(instances["AutoMinorVersionUpgrade"])
        # this is a failing check
        if minorVersionUpgradeCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{neptuneInstanceArn}/neptune-instance-minor-version-auto-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Neptune.7] Neptune database instances should be protected from deletion",
                "Description": f"Neptune database instance {neptuneDbId} does not have minor version auto-updates enabled. Periodically, Neptune performs maintenance on Neptune resources. Maintenance most often involves updates to the DB cluster's underlying operating system or database engine version. Updates to the operating system most often occur for security issues and should be done as soon as possible. DB instances are not automatically backed up when an OS update is applied. So you should back up your DB instances before you apply an update. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune minor version auto-updates and maintainance refer to the Maintaining an Amazon Neptune DB Cluster section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-maintaining.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                        "ISO 27001:2013 A.11.2.6"
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
                "Id": f"{neptuneInstanceArn}/neptune-instance-minor-version-auto-update-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": neptuneInstanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Neptune.7] Neptune database instances should be protected from deletion",
                "Description": f"Neptune database instance {neptuneDbId} has minor version auto-updates enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Neptune minor version auto-updates and maintainance refer to the Maintaining an Amazon Neptune DB Cluster section of the Amazon Neptune User Guide",
                        "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-maintaining.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsNeptuneDbInstance",
                        "Id": neptuneInstanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "DBInstanceIdentifier": neptuneDbId,
                                "DBInstanceClass": instances["DBInstanceClass"],
                                "Engine": instances["Engine"],
                                "MasterUsername": instances["MasterUsername"],
                                "Address": instances["Endpoint"]["Address"],
                                "Port": str(instances["Endpoint"]["Port"]),
                                "InstanceCreateTime": str(instances["InstanceCreateTime"]),
                                "AvailabilityZone": instances["AvailabilityZone"],
                                "DBSubnetGroupName": instances["DBSubnetGroup"]["DBSubnetGroupName"],
                                "DBSubnetGroupVpcId": instances["DBSubnetGroup"]["VpcId"]
                                
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
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("neptune")
def neptune_cluster_autoscaling_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.8] Neptune clusters should be configured for auto-scaling"""
    neptune = session.client("neptune")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_db_clusters(cache, session)["DBClusters"]:
        clusterArn = cluster["DBClusterArn"]
        clusterId = cluster["DBClusterIdentifier"]
        clusterParameterGroupName = cluster["DBClusterParameterGroup"]
        # Retrieve the Parameters from the Cluster Parameter Group
        for param in neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=clusterParameterGroupName)["Parameters"]:
            if param["ParameterName"] == "neptune_autoscaling_config":
                # by default the value will be blank, as the parameter requires a complex escaped JSON object, we will assume anything other than an empty value is that...
                # this is a failing check
                if param["ParameterValue"] == "":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/neptune-cluster-autoscaling-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[Neptune.8] Neptune clusters should be configured for auto-scaling",
                        "Description": f"Neptune cluster {clusterId} does not have auto-scaling configured. You can use Neptune auto-scaling to automatically adjust the number of Neptune replicas in a DB cluster, to meet your connectivity and workload requirements. Auto-scaling lets your Neptune DB cluster handle sudden increases in workload, and then, when the workload decreases, auto-scaling removes unnecessary replicas so you aren't paying for unused capacity. Using the neptune_autoscaling_config DB cluster parameter, you can also specify the instance type of the new read-replicas that Neptune auto-scaling creates, the maintenance windows for those read-replicas, and tags to be associated with each of the new read-replicas. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Neptune auto-scaling and defining the parameter JSON refer to the Auto-scaling the number of replicas in an Amazon Neptune DB cluster section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-autoscaling.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneDbCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "DBClusterIdentifier": clusterId,
                                        "AvailabilityZones": str(cluster["AvailabilityZones"]),
                                        "DBClusterParameterGroup": clusterParameterGroupName,
                                        "DBSubnetGroup": cluster["DBSubnetGroup"],
                                        "Status": cluster["Status"],
                                        "Endpoint": cluster["Endpoint"],
                                        "ReaderEndpoint": cluster["ReaderEndpoint"],
                                        "Engine": cluster["Engine"],
                                        "EngineVersion": cluster["EngineVersion"],
                                        "Port": str(cluster["Port"]),
                                        "MasterUsername": cluster["MasterUsername"],
                                        "DbClusterResourceId": cluster["DbClusterResourceId"],
                                        "ClusterCreateTime": str(cluster["ClusterCreateTime"])
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
                        "Id": f"{clusterArn}/neptune-cluster-autoscaling-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.8] Neptune clusters should be configured for auto-scaling",
                        "Description": f"Neptune cluster {clusterId} has auto-scaling configured.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Neptune auto-scaling and defining the parameter JSON refer to the Auto-scaling the number of replicas in an Amazon Neptune DB cluster section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-autoscaling.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneDbCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "DBClusterIdentifier": clusterId,
                                        "AvailabilityZones": str(cluster["AvailabilityZones"]),
                                        "DBClusterParameterGroup": clusterParameterGroupName,
                                        "DBSubnetGroup": cluster["DBSubnetGroup"],
                                        "Status": cluster["Status"],
                                        "Endpoint": cluster["Endpoint"],
                                        "ReaderEndpoint": cluster["ReaderEndpoint"],
                                        "Engine": cluster["Engine"],
                                        "EngineVersion": cluster["EngineVersion"],
                                        "Port": str(cluster["Port"]),
                                        "MasterUsername": cluster["MasterUsername"],
                                        "DbClusterResourceId": cluster["DbClusterResourceId"],
                                        "ClusterCreateTime": str(cluster["ClusterCreateTime"])
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
                # end the loop
                break
            else:
                continue

@registry.register_check("neptune")
def neptune_cluster_gremlin_query_result_cache_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Neptune.9] Neptune clusters should be configured for Gremlin result caching"""
    neptune = session.client("neptune")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_db_clusters(cache, session)["DBClusters"]:
        clusterArn = cluster["DBClusterArn"]
        clusterId = cluster["DBClusterIdentifier"]
        clusterParameterGroupName = cluster["DBClusterParameterGroup"]
        # Retrieve the Parameters from the Cluster Parameter Group
        for param in neptune.describe_db_cluster_parameters(DBClusterParameterGroupName=clusterParameterGroupName)["Parameters"]:
            if param["ParameterName"] == "neptune_result_cache":
                # this is a failing check
                if param["ParameterValue"] == "0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/neptune-cluster-results-caching-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.9] Neptune clusters should be configured for Gremlin result caching",
                        "Description": f"Neptune cluster {clusterId} does not have query caching for Gremlin configured. You can enable the query results cache and then use a query hint to cache the results of a Gremlin read-only query. Any re-run of the query then retrieves the cached results with low latency and no I/O costs, as long as they are still in the cache. This works for queries submitted both on an HTTP endpoint and using Websockets, either as byte-code or in string form. NOTE: The query-results cache is not available on t2.medium ort3.medium instance types. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Neptune results caching for Gremlin and defining the parameter refer to the Caching query results in Amazon Neptune Gremlin section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-results-cache.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneDbCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "DBClusterIdentifier": clusterId,
                                        "AvailabilityZones": str(cluster["AvailabilityZones"]),
                                        "DBClusterParameterGroup": clusterParameterGroupName,
                                        "DBSubnetGroup": cluster["DBSubnetGroup"],
                                        "Status": cluster["Status"],
                                        "Endpoint": cluster["Endpoint"],
                                        "ReaderEndpoint": cluster["ReaderEndpoint"],
                                        "Engine": cluster["Engine"],
                                        "EngineVersion": cluster["EngineVersion"],
                                        "Port": str(cluster["Port"]),
                                        "MasterUsername": cluster["MasterUsername"],
                                        "DbClusterResourceId": cluster["DbClusterResourceId"],
                                        "ClusterCreateTime": str(cluster["ClusterCreateTime"])
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
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{clusterArn}/neptune-cluster-results-caching-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": clusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Neptune.9] Neptune clusters should be configured for Gremlin result caching",
                        "Description": f"Neptune cluster {clusterId} has query caching for Gremlin configured.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Neptune results caching for Gremlin and defining the parameter refer to the Caching query results in Amazon Neptune Gremlin section of the Amazon Neptune User Guide.",
                                "Url": "https://docs.aws.amazon.com/neptune/latest/userguide/gremlin-results-cache.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsNeptuneDbCluster",
                                "Id": clusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "DBClusterIdentifier": clusterId,
                                        "AvailabilityZones": str(cluster["AvailabilityZones"]),
                                        "DBClusterParameterGroup": clusterParameterGroupName,
                                        "DBSubnetGroup": cluster["DBSubnetGroup"],
                                        "Status": cluster["Status"],
                                        "Endpoint": cluster["Endpoint"],
                                        "ReaderEndpoint": cluster["ReaderEndpoint"],
                                        "Engine": cluster["Engine"],
                                        "EngineVersion": cluster["EngineVersion"],
                                        "Port": str(cluster["Port"]),
                                        "MasterUsername": cluster["MasterUsername"],
                                        "DbClusterResourceId": cluster["DbClusterResourceId"],
                                        "ClusterCreateTime": str(cluster["ClusterCreateTime"])
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
                # end the loop
                break
            else:
                continue