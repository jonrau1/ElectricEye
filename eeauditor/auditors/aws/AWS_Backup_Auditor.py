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
# import boto3 clients
sts = boto3.client("sts")
ec2 = boto3.client("ec2")
dynamodb = boto3.client("dynamodb")
rds = boto3.client("rds")
efs = boto3.client("efs")
backup = boto3.client("backup")

# loop through DynamoDB tables


def paginate(cache):
    response = cache.get("paginate")
    if response:
        return response
    get_paginators = dynamodb.get_paginator('list_tables')
    if get_paginators:
        cache["paginate"] = get_paginators.paginate()
        return cache["paginate"]


@registry.register_check("backup")
def volume_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through available or in-use ebs volumes
    response = ec2.describe_volumes(
        Filters=[{"Name": "status", "Values": ["available", "in-use"]}]
    )
    myEbsVolumes = response["Volumes"]
    for volumes in myEbsVolumes:
        volumeId = str(volumes["VolumeId"])
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        try:
            # check if ebs volumes are backed up
            response = backup.describe_protected_resource(
                ResourceArn=volumeArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": volumeArn + "/ebs-backups",
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
                "Description": "EBS volume " + volumeId + " is protected by AWS Backup",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"volumeId": volumeId}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": volumeArn + "/ebs-backups",
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
                "Description": "EBS volume "
                + volumeId
                + " is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EBS volumes",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"volumeId": volumeId}},
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


@registry.register_check("ec2")
def ec2_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through ec2 instances
    response = ec2.describe_instances(DryRun=False)
    myReservations = response["Reservations"]
    for reservations in myReservations:
        myInstances = reservations["Instances"]
        for instances in myInstances:
            instanceId = str(instances["InstanceId"])
            instanceType = str(instances["InstanceType"])
            imageId = str(instances["ImageId"])
            subnetId = str(instances["SubnetId"])
            vpcId = str(instances["VpcId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            try:
                # check if ec2 instances are backed up
                response = backup.describe_protected_resource(
                    ResourceArn=instanceArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-backups",
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
                    "Description": "EC2 instance " + instanceId + " is protected by AWS Backup.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": imageId,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
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
            except:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-backups",
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
                    "Description": "EC2 instance "
                    + instanceId
                    + " is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EC2 instances",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": imageId,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
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


@registry.register_check("dynamodb")
def ddb_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    iterator = paginate(cache=cache)
    for page in iterator:
        for table in page['TableNames']:
            response = dynamodb.describe_table(TableName=table)
            tableArn = str(response["Table"]["TableArn"])
            tableName = str(response["Table"]["TableName"])
            iso8601Time = datetime.datetime.utcnow().replace(
                tzinfo=datetime.timezone.utc).isoformat()
            try:
                # check if ddb tables are backed up
                response = backup.describe_protected_resource(
                    ResourceArn=tableArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": tableArn + "/dynamodb-backups",
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
                    "Description": "DynamoDB table " + tableName + " is protected by AWS Backup.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsDynamoDbTable",
                            "Id": tableArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"tableName": tableName}},
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
            except:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": tableArn + "/dynamodb-backups",
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
                    "Description": "DynamoDB table "
                    + tableName
                    + " is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for DynamoDB tables",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                            "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsDynamoDbTable",
                            "Id": tableArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"tableName": tableName}},
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


@registry.register_check("backup")
def reds_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through rds db instances
    response = rds.describe_db_instances(
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
    myRdsInstances = response["DBInstances"]
    for databases in myRdsInstances:
        dbArn = str(databases["DBInstanceArn"])
        dbId = str(databases["DBInstanceIdentifier"])
        dbEngine = str(databases["Engine"])
        dbEngineVersion = str(databases["EngineVersion"])
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        try:
            # check if db instances are backed up
            response = backup.describe_protected_resource(ResourceArn=dbArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": dbArn + "/rds-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Backup.4] RDS database instances should be protected by AWS Backup",
                "Description": "RDS database instance " + dbId + " is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": dbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": dbId,
                                "Engine": dbEngine,
                                "EngineVersion": dbEngineVersion,
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": dbArn + "/rds-backups",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": dbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Backup.4] RDS database instances should be protected by AWS Backup",
                "Description": "RDS database instance "
                + dbId
                + " is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for RDS instances",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsRdsDbInstance",
                        "Id": dbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsRdsDbInstance": {
                                "DBInstanceIdentifier": dbId,
                                "Engine": dbEngine,
                                "EngineVersion": dbEngineVersion,
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


@registry.register_check("backup")
def efs_backup_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    # loop through EFS file systems
    response = efs.describe_file_systems()
    myFileSys = response["FileSystems"]
    for filesys in myFileSys:
        fileSysId = str(filesys["FileSystemId"])
        fileSysArn = f"arn:{awsPartition}:elasticfilesystem:{awsRegion}:{awsAccountId}:file-system/{fileSysId}"
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        try:
            # check if db instances are backed up
            response = backup.describe_protected_resource(
                ResourceArn=fileSysArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": fileSysArn + "/efs-backups",
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
                "Description": "EFS file system " + fileSysId + " is protected by AWS Backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElasticFileSystem",
                        "Id": fileSysArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"fileSystemId": fileSysId}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": fileSysArn + "/efs-backups",
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
                "Description": "EFS file system "
                + fileSysId
                + " is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EFS file systems.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide",
                        "Url": "https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElasticFileSystem",
                        "Id": fileSysArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"fileSystemId": fileSysId}},
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
