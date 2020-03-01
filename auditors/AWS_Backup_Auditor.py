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
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')
ec2 = boto3.client('ec2')
dynamodb = boto3.client('dynamodb')
rds = boto3.client('rds')
efs = boto3.client('efs')
backup = boto3.client('backup')
# create env vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def volume_backup_check():
    # loop through available or in-use ebs volumes
    response = ec2.describe_volumes(Filters=[{'Name': 'status','Values': ['available', 'in-use']}])
    myEbsVolumes = response['Volumes']
    for volumes in myEbsVolumes:
        volumeId = str(volumes['VolumeId'])
        volumeArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':volume/' + volumeId
        try:
            # check if ebs volumes are backed up
            response = backup.describe_protected_resource(ResourceArn=volumeArn)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': volumeArn + '/ebs-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': volumeArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Backup.1] EBS volumes should be protected by AWS Backup',
                            'Description': 'EBS volume ' + volumeId + ' is protected by AWS Backup',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Volume',
                                    'Id': volumeArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'VolumeId': volumeId }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': volumeArn + '/ebs-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': volumeArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Backup.1] EBS volumes should be protected by AWS Backup',
                            'Description': 'EBS volume ' + volumeId + ' is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EBS volumes',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Volume',
                                    'Id': volumeArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'VolumeId': volumeId }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def ec2_backup_check():
    # loop through ec2 instances
    response = ec2.describe_instances(DryRun=False)
    myReservations = response['Reservations']
    for reservations in myReservations:
        myInstances = reservations['Instances']
        for instances in myInstances:
            instanceId = str(instances['InstanceId'])
            instanceType = str(instances['InstanceType'])
            imageId = str(instances['ImageId'])
            subnetId = str(instances['SubnetId'])
            vpcId = str(instances['VpcId'])
            instanceArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':instance/' + instanceId
            try:
                # check if ec2 instances are backed up
                response = backup.describe_protected_resource(ResourceArn=instanceArn)
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/ec2-backups',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[Backup.2] EC2 instances should be protected by AWS Backup',
                                'Description': 'EC2 instance ' + instanceId + ' is protected by AWS Backup.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Instance',
                                        'Id': instanceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsEc2Instance': {
                                                'Type': instanceType,
                                                'ImageId': imageId,
                                                'VpcId': vpcId,
                                                'SubnetId': subnetId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'PASSED' },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            except:
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/ec2-backups',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 40 },
                                'Confidence': 99,
                                'Title': '[Backup.2] EC2 instances should be protected by AWS Backup',
                                'Description': 'EC2 instance ' + instanceId + ' is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EC2 instances',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Instance',
                                        'Id': instanceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsEc2Instance': {
                                                'Type': instanceType,
                                                'ImageId': imageId,
                                                'VpcId': vpcId,
                                                'SubnetId': subnetId
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 'Status': 'FAILED' },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)

def ddb_backup_check():
    # loop through dynamodb tables
    response = dynamodb.list_tables()
    myDdbTables = response['TableNames']
    for tables in myDdbTables:
        response = dynamodb.describe_table(TableName=tables)
        tableArn = str(response['Table']['TableArn'])
        tableName = str(response['Table']['TableName'])
        try:
            # check if ddb tables are backed up
            response = backup.describe_protected_resource(ResourceArn=tableArn)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': tableArn + '/dynamodb-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': tableArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Backup.3] DynamoDB tables should be protected by AWS Backup',
                            'Description': 'DynamoDB table ' + tableName + ' is protected by AWS Backup.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsDynamoDbTable',
                                    'Id': tableArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'TableName': tableName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': tableArn + '/dynamodb-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': tableArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Backup.3] DynamoDB tables should be protected by AWS Backup',
                            'Description': 'DynamoDB table ' + tableName + ' is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for DynamoDB tables',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsDynamoDbTable',
                                    'Id': tableArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'TableName': tableName }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
            
def rds_backup_check():
    # loop through rds db instances
    response = rds.describe_db_instances(
        Filters=[
            {
                'Name': 'engine',
                'Values': [
                    'aurora',
                    'aurora-mysql',
                    'aurora-postgresql',
                    'mariadb',
                    'mysql',
                    'oracle-ee',
                    'postgres',
                    'sqlserver-ee',
                    'sqlserver-se',
                    'sqlserver-ex',
                    'sqlserver-web'
                ]
            }
        ],
        MaxRecords=100
    )
    myRdsInstances = response['DBInstances']
    for databases in myRdsInstances:
        dbArn = str(databases['DBInstanceArn'])
        dbId = str(databases['DBInstanceIdentifier'])
        dbEngine = str(databases['Engine'])
        dbEngineVersion = str(databases['EngineVersion'])
        try:
            # check if db instances are backed up
            response = backup.describe_protected_resource(ResourceArn=dbArn)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dbArn + '/rds-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Backup.4] RDS database instances should be protected by AWS Backup',
                            'Description': 'RDS database instance ' + dbId + ' is protected by AWS Backup.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': dbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': dbId,
                                            'Engine': dbEngine,
                                            'EngineVersion': dbEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': dbArn + '/rds-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': dbArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Backup.4] RDS database instances should be protected by AWS Backup',
                            'Description': 'RDS database instance ' + dbId + ' is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for RDS instances',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': dbArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': dbId,
                                            'Engine': dbEngine,
                                            'EngineVersion': dbEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def efs_backup_check():
    # loop through EFS file systems
    response = efs.describe_file_systems()
    myFileSys = response['FileSystems']
    for filesys in myFileSys:
        fileSysId = str(filesys['FileSystemId'])
        fileSysArn = 'arn:aws:elasticfilesystem:' + awsRegion + ':' + awsAccountId + ':file-system/' + fileSysId
        try:
            # check if db instances are backed up
            response = backup.describe_protected_resource(ResourceArn=fileSysArn)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fileSysArn + '/efs-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': fileSysArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Backup.5] EFS file systems should be protected by AWS Backup',
                            'Description': 'EFS file system ' + fileSysId + ' is protected by AWS Backup.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': fileSysArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'FileSystemId': fileSysId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fileSysArn + '/efs-backups',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': fileSysArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Backup.5] EFS file systems should be protected by AWS Backup',
                            'Description': 'EFS file system ' + fileSysId + ' is not protected by AWS Backup. Refer to the remediation instructions for information on ensuring disaster recovery and business continuity requirements are fulfilled for EFS file systems.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on creating scheduled backups refer to the Assign Resources to a Backup Plan section of the AWS Backup Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/create-a-scheduled-backup.html#assign-resources-to-plan'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': fileSysArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'FileSystemId': fileSysId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 'Status': 'FAILED' },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
            
def backup_auditor():
    ec2_backup_check()
    volume_backup_check()
    ddb_backup_check()
    rds_backup_check()
    efs_backup_check
    
backup_auditor()