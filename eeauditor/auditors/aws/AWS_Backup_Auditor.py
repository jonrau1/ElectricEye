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
import botocore.exceptions
from dateutil.parser import parse
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def describe_volumes(cache, session):
    ec2 = session.client("ec2")
    response = cache.get("describe_volumes")
    if response:
        return response
    cache["describe_volumes"] = ec2.describe_volumes(
        DryRun=False,
        MaxResults=500,
        Filters=[{"Name": "status", "Values": ["available", "in-use"]}]
    )
    return cache["describe_volumes"]

# loop through *running & stopped& EC2 instances
def describe_instances(cache, session):
    ec2 = session.client("ec2")
    instanceList = []
    response = cache.get("instances")
    if response:
        return response
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name","Values": ["running","stopped"]}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)
        cache["instances"] = instanceList
        return cache["instances"]

# loop through DynamoDB tables
def list_tables(cache, session):
    dynamodb = session.client("dynamodb")
    ddbTables = []
    response = cache.get("list_tables")
    if response:
        return response
    paginator = dynamodb.get_paginator("list_tables")
    if paginator:
        for page in paginator.paginate():
            for cluster in page["TableNames"]:
                ddbTables.append(cluster)
        cache["list_tables"] = ddbTables
        return cache["list_tables"]

# loop through RDS/Aurora DB Instances
def describe_db_instances(cache, session):
    rds = session.client("rds")
    dbInstances = []
    response = cache.get("describe_db_instances")
    if response:
        return response
    paginator = rds.get_paginator('describe_db_instances')
    if paginator:
        for page in paginator.paginate(
            Filters=[
                {
                    "Name": "engine",
                    "Values": [
                        "aurora-mysql",
                        "aurora-postgresql",
                        "mariadb",
                        "mysql",
                        "oracle-ee",
                        "oracle-ee-cdb",
                        "oracle-se2",
                        "oracle-se2-cdb",
                        "postgres",
                        "sqlserver-ee",
                        "sqlserver-se",
                        "sqlserver-ex",
                        "sqlserver-web",
                        "custom-sqlserver-ee",
                        "custom-sqlserver-se",
                        "custom-sqlserver-web"
                    ]
                }
            ]
        ):
            for dbinstance in page["DBInstances"]:
                dbInstances.append(dbinstance)
    cache["describe_db_instances"] = dbInstances
    return cache["describe_db_instances"]

# loop through EFS file systems
def describe_file_systems(cache, session):
    efs = session.client("efs")
    response = cache.get("describe_file_systems")
    if response:
        return response
    cache["describe_file_systems"] = efs.describe_file_systems()
    return cache["describe_file_systems"]

# loop through Neptune clusters
def describe_neptune_db_clusters(cache, session):
    neptune = session.client("neptune")
    response = cache.get("describe_db_clusters")
    if response:
        return response
    cache["describe_db_clusters"] = neptune.describe_db_clusters(
        Filters=[{"Name": "engine", "Values": ["neptune"]}]
    )
    return cache["describe_db_clusters"]

# loop through DocDb clusters
def describe_doc_db_clusters(cache, session):
    response = cache.get("describe_db_clusters")
    docdb = session.client("docdb")
    if response:
        return response
    cache["describe_db_clusters"] = docdb.describe_db_clusters(
        Filters=[{"Name": "engine", "Values": ["docdb"]}]
    )
    return cache["describe_db_clusters"]

@registry.register_check("backup")
def volume_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.1] EBS volumes should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for volumes in describe_volumes(cache, session)["Volumes"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volumes,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        volumeId = str(volumes["VolumeId"])
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        # this is a passing check
        try:
            backup.describe_protected_resource(ResourceArn=volumeArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{volumeArn}/ebs-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": volumeArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.1] EBS volumes should be protected by AWS Backup",
                "Description": f"EBS volume {volumeId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
        # this is a failing check
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{volumeArn}/ebs-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": volumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.1] EBS volumes should be protected by AWS Backup",
                    "Description": f"EBS volume {volumeId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EBS volumes.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Volume"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": volumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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

@registry.register_check("backup")
def ec2_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.2] EC2 instances should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        # this is a passing check
        try:
            backup.describe_protected_resource(ResourceArn=instanceArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.2] EC2 instances should be protected by AWS Backup",
                "Description": f"EC2 instance {instanceId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
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
        # this is a failing check
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{instanceArn}/ec2-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.2] EC2 instances should be protected by AWS Backup",
                    "Description": f"EC2 instance {instanceId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EC2 instances.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
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

@registry.register_check("backup")
def ddb_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.3] DynamoDB tables should be protected by AWS Backup"""
    backup = session.client("backup")
    dynamodb = session.client("dynamodb")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for table in list_tables(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(table,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        response = dynamodb.describe_table(TableName=table)
        tableArn = str(response["Table"]["TableArn"])
        tableName = str(response["Table"]["TableName"])
        # this is a passing check
        try:
            backup.describe_protected_resource(ResourceArn=tableArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tableArn}/dynamodb-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": tableArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.3] DynamoDB tables should be protected by AWS Backup",
                "Description": f"DynamoDB table {tableName} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                    "AssetService": "Amazon DynamoDB",
                    "AssetComponent": "Table"
                },
                "Resources": [
                    {
                        "Type": "AwsDynamoDbTable",
                        "Id": tableArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsDynamoDbTable": {
                                "TableName": tableName
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
        # this is a failing check
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{tableArn}/dynamodb-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": tableArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.3] DynamoDB tables should be protected by AWS Backup",
                    "Description": f"DynamoDB table {tableName} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for DynamoDB tables.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                        "AssetService": "Amazon DynamoDB",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsDynamoDbTable",
                            "Id": tableArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsDynamoDbTable": {
                                    "TableName": tableName
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

@registry.register_check("backup")
def rds_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.4] RDS database instances should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for dbinstances in describe_db_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dbinstances,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceArn = str(dbinstances["DBInstanceArn"])
        instanceId = str(dbinstances["DBInstanceIdentifier"])
        instanceClass = str(dbinstances["DBInstanceClass"])
        instancePort = int(dbinstances["Endpoint"]["Port"])
        instanceEngine = str(dbinstances["Engine"])
        instanceEngineVersion = str(dbinstances["EngineVersion"])
        # this is a passing check
        try:
            backup.describe_protected_resource(ResourceArn=instanceArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/rds-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.4] RDS database instances should be protected by AWS Backup",
                "Description": f"RDS database instance {instanceId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                    "AssetService": "Amazon Relational Database Service",
                    "AssetComponent": "Database Instance"
                },
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
        # this is a failing check
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{instanceArn}/rds-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.4] RDS database instances should be protected by AWS Backup",
                    "Description": f"RDS database instance {instanceId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for RDS instances.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                        "AssetService": "Amazon Relational Database Service",
                        "AssetComponent": "Database Instance"
                    },
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

@registry.register_check("backup")
def efs_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.5] EFS file systems should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for filesys in describe_file_systems(cache, session)["FileSystems"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(filesys,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        fileSysId = str(filesys["FileSystemId"])
        fileSysArn = f"arn:{awsPartition}:elasticfilesystem:{awsRegion}:{awsAccountId}:file-system/{fileSysId}"
        # this is a passing check
        try:
            backup.describe_protected_resource(ResourceArn=fileSysArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{fileSysArn}/efs-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": fileSysArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.5] EFS file systems should be protected by AWS Backup",
                "Description": f"EFS file system {fileSysId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic File System",
                    "AssetComponent": "File System"
                },
                "Resources": [
                    {
                        "Type": "AwsElasticFileSystem",
                        "Id": fileSysArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
        # this is a failing check
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{fileSysArn}/efs-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": fileSysArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.5] EFS file systems should be protected by AWS Backup",
                    "Description": f"EFS file system {fileSysId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EFS file systems.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon Elastic File System",
                        "AssetComponent": "File System"
                    },
                    "Resources": [
                        {
                            "Type": "AwsElasticFileSystem",
                            "Id": fileSysArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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

@registry.register_check("backup")
def neptune_cluster_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.6] Neptune clusters should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cluster in describe_neptune_db_clusters(cache, session)["DBClusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clusterArn = cluster["DBClusterArn"]
        clusterId = cluster["DBClusterIdentifier"]
        clusterParameterGroupName = cluster["DBClusterParameterGroup"]
        try:
            backup.describe_protected_resource(ResourceArn=clusterArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{clusterArn}/neptune-cluster-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.6] Neptune clusters should be protected by AWS Backup",
                "Description": f"Neptune cluster {clusterId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                    "AssetService": "Amazon Neptune",
                    "AssetComponent": "Database Cluster"
                },
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
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{clusterArn}/neptune-cluster-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.6] Neptune clusters should be protected by AWS Backup",
                    "Description": f"Neptune cluster {clusterId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for Neptune clusters.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                        "AssetService": "Amazon Neptune",
                        "AssetComponent": "Database Cluster"
                    },
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

@registry.register_check("backup")
def docdb_cluster_backup_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Backup.7] DocumentDB clusters should be protected by AWS Backup"""
    backup = session.client("backup")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for docdbcluster in describe_doc_db_clusters(cache, session)["DBClusters"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(docdbcluster,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        docdbclusterId = str(docdbcluster["DBClusterIdentifier"])
        docdbClusterArn = str(docdbcluster["DBClusterArn"])
        try:
            backup.describe_protected_resource(ResourceArn=docdbClusterArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{docdbClusterArn}/docdb-cluster-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": docdbClusterArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.7] DocumentDB clusters should be protected by AWS Backup",
                "Description": f"DocumentDB cluster {docdbclusterId} is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                    "AssetService": "Amazon DocumentDB",
                    "AssetComponent": "Database Cluster"
                },
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
        except botocore.exceptions.ClientError as error:
            # Handle "ResourceNotFoundException" exception which means the resource is not protected
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{docdbClusterArn}/docdb-cluster-backups",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": docdbClusterArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Backup.7] DocumentDB clusters should be protected by AWS Backup",
                    "Description": f"DocumentDB cluster {docdbclusterId} is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for DocumentDB clusters.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
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
                        "AssetService": "Amazon DocumentDB",
                        "AssetComponent": "Database Cluster"
                    },
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