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
rds = boto3.client('rds')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through all RDS DB instances
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
# loop through all RDS DB snapshots
response = rds.describe_db_snapshots()
myRdsSnapshots = response['DBSnapshots']

def rds_instance_ha_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        highAvailabilityCheck = str(dbinstances['MultiAZ'])
        if highAvailabilityCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-ha-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[RDS.1] RDS instances should be configured for high availability',
                            'Description': 'RDS DB instance ' + instanceId + ' is not configured for high availability. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS instance high availability and how to configure it refer to the High Availability (Multi-AZ) for Amazon RDS section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-ha-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[RDS.1] RDS instances should be configured for high availability',
                            'Description': 'RDS DB instance ' + instanceId + ' is configured for high availability.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS instance high availability and how to configure it refer to the High Availability (Multi-AZ) for Amazon RDS section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_public_access_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        publicAccessibleCheck = str(dbinstances['PubliclyAccessible'])
        if publicAccessibleCheck == 'True':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-public-access-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'CRITICAL' },
                            'Confidence': 99,
                            'Title': '[RDS.2] RDS instances should not be publicly accessible',
                            'Description': 'RDS DB instance ' + instanceId + ' is publicly accessible. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS instance publicly access and how to change it refer to the Hiding a DB Instance in a VPC from the Internet section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion,
                                            'PubliclyAccessible': True
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3',
                                    'NIST SP 800-53 AC-1',
                                    'NIST SP 800-53 AC-17',
                                    'NIST SP 800-53 AC-19',
                                    'NIST SP 800-53 AC-20',
                                    'NIST SP 800-53 SC-15',
                                    'AICPA TSC CC6.6',
                                    'ISO 27001:2013 A.6.2.1',
                                    'ISO 27001:2013 A.6.2.2',
                                    'ISO 27001:2013 A.11.2.6',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-public-access-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.2] RDS instances should not be publicly accessible',
                            'Description': 'RDS DB instance ' + instanceId + ' is not publicly accessible. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS instance publicly access and how to change it refer to the Hiding a DB Instance in a VPC from the Internet section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html#USER_VPC.Hiding'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion,
                                            'PubliclyAccessible': False
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.AC-3',
                                    'NIST SP 800-53 AC-1',
                                    'NIST SP 800-53 AC-17',
                                    'NIST SP 800-53 AC-19',
                                    'NIST SP 800-53 AC-20',
                                    'NIST SP 800-53 SC-15',
                                    'AICPA TSC CC6.6',
                                    'ISO 27001:2013 A.6.2.1',
                                    'ISO 27001:2013 A.6.2.2',
                                    'ISO 27001:2013 A.11.2.6',
                                    'ISO 27001:2013 A.13.1.1',
                                    'ISO 27001:2013 A.13.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_storage_encryption_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        rdsStorageEncryptionCheck = str(dbinstances['StorageEncrypted'])
        if rdsStorageEncryptionCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-storage-encryption-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[RDS.3] RDS instances should have encrypted storage',
                            'Description': 'RDS DB instance ' + instanceId + ' does not have encrypted storage. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS storage encryption refer to the Enabling Amazon RDS Encryption for a DB Instance section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion,
                                            'StorageEncrypted': False
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.DS-1', 
                                    'NIST SP 800-53 MP-8',
                                    'NIST SP 800-53 SC-12',
                                    'NIST SP 800-53 SC-28',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.2.3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-storage-encryption-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.3] RDS instances should have encrypted storage',
                            'Description': 'RDS DB instance ' + instanceId + ' has encrypted storage.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS storage encryption refer to the Enabling Amazon RDS Encryption for a DB Instance section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion,
                                            'StorageEncrypted': True
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.DS-1', 
                                    'NIST SP 800-53 MP-8',
                                    'NIST SP 800-53 SC-12',
                                    'NIST SP 800-53 SC-28',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.2.3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_iam_auth_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        iamDbAuthCheck = str(dbinstances['IAMDatabaseAuthenticationEnabled'])
        if instanceEngine == 'mysql' or 'postgres':
            if iamDbAuthCheck == 'False':
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/instance-iam-auth-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'MEDIUM' },
                                'Confidence': 99,
                                'Title': '[RDS.4] RDS instances that support IAM Authentication should use IAM Authentication',
                                'Description': 'RDS DB instance ' + instanceId + ' does not support IAM Authentication. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on RDS IAM Database Authentication and how to configure it refer to the IAM Database Authentication for MySQL and PostgreSQL section of the Amazon Relational Database Service User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsRdsDbInstance',
                                        'Id': instanceArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsRdsDbInstance': {
                                                'DBInstanceIdentifier': instanceId,
                                                'DBInstanceClass': instanceClass,
                                                'DbInstancePort': instancePort,
                                                'Engine': instanceEngine,
                                                'EngineVersion': instanceEngineVersion,
                                                'IAMDatabaseAuthenticationEnabled': False
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-6',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-2',
                                        'NIST SP 800-53 AC-3',
                                        'NIST SP 800-53 AC-16',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-24',
                                        'NIST SP 800-53 IA-1',
                                        'NIST SP 800-53 IA-2',
                                        'NIST SP 800-53 IA-4',
                                        'NIST SP 800-53 IA-5',
                                        'NIST SP 800-53 IA-8',
                                        'NIST SP 800-53 PE-2',
                                        'NIST SP 800-53 PS-3',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.7.1.1',
                                        'ISO 27001:2013 A.9.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/instance-iam-auth-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[RDS.4] RDS instances that support IAM Authentication should use IAM Authentication',
                                'Description': 'RDS DB instance ' + instanceId + ' supports IAM Authentication.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on RDS IAM Database Authentication and how to configure it refer to the IAM Database Authentication for MySQL and PostgreSQL section of the Amazon Relational Database Service User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsRdsDbInstance',
                                        'Id': instanceArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsRdsDbInstance': {
                                                'DBInstanceIdentifier': instanceId,
                                                'DBInstanceClass': instanceClass,
                                                'DbInstancePort': instancePort,
                                                'Engine': instanceEngine,
                                                'EngineVersion': instanceEngineVersion,
                                                'IAMDatabaseAuthenticationEnabled': True
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-6',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-2',
                                        'NIST SP 800-53 AC-3',
                                        'NIST SP 800-53 AC-16',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-24',
                                        'NIST SP 800-53 IA-1',
                                        'NIST SP 800-53 IA-2',
                                        'NIST SP 800-53 IA-4',
                                        'NIST SP 800-53 IA-5',
                                        'NIST SP 800-53 IA-8',
                                        'NIST SP 800-53 PE-2',
                                        'NIST SP 800-53 PS-3',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.7.1.1',
                                        'ISO 27001:2013 A.9.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        else:
            pass

def rds_instance_domain_join_check(): 
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        activeDirectoryDomainCheck = str(dbinstances['DomainMemberships'])
        if instanceEngine == 'mysql' or 'oracle-ee' or 'oracle-se1' or 'oracle-se2' or 'oracle-se' or 'postgres' or 'sqlserver-ee' or 'sqlserver-se' or 'sqlserver-ex' or 'sqlserver-web':
            if activeDirectoryDomainCheck == '[]':
                try:
                    # this one doesn't have a domain so likely doesnt have kerberos
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/instance-domain-join-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'MEDIUM' },
                                'Confidence': 99,
                                'Title': '[RDS.5] RDS instances that support Kerberos Authentication should be joined to a domain',
                                'Description': 'RDS DB instance ' + instanceId + ' is not joined to a domain, and likely does not support Kerberos Authentication because of it. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on RDS instances that support Kerberos Authentication and how to configure it refer to the Kerberos Authentication section of the Amazon Relational Database Service User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/kerberos-authentication.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsRdsDbInstance',
                                        'Id': instanceArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsRdsDbInstance': {
                                                'DBInstanceIdentifier': instanceId,
                                                'DBInstanceClass': instanceClass,
                                                'DbInstancePort': instancePort,
                                                'Engine': instanceEngine,
                                                'EngineVersion': instanceEngineVersion
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'FAILED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-6',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-2',
                                        'NIST SP 800-53 AC-3',
                                        'NIST SP 800-53 AC-16',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-24',
                                        'NIST SP 800-53 IA-1',
                                        'NIST SP 800-53 IA-2',
                                        'NIST SP 800-53 IA-4',
                                        'NIST SP 800-53 IA-5',
                                        'NIST SP 800-53 IA-8',
                                        'NIST SP 800-53 PE-2',
                                        'NIST SP 800-53 PS-3',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.7.1.1',
                                        'ISO 27001:2013 A.9.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'NEW'
                                },
                                'RecordState': 'ACTIVE'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                try:
                    # this one doesn't have a domain so likely doesnt have kerberos
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': instanceArn + '/instance-domain-join-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[RDS.5] RDS instances that support Kerberos Authentication should be joined to a domain',
                                'Description': 'RDS DB instance ' + instanceId + ' is joined to a domain, and likely supports Kerberos Authentication because of it.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on RDS instances that support Kerberos Authentication and how to configure it refer to the Kerberos Authentication section of the Amazon Relational Database Service User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/kerberos-authentication.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsRdsDbInstance',
                                        'Id': instanceArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'AwsRdsDbInstance': {
                                                'DBInstanceIdentifier': instanceId,
                                                'DBInstanceClass': instanceClass,
                                                'DbInstancePort': instancePort,
                                                'Engine': instanceEngine,
                                                'EngineVersion': instanceEngineVersion
                                            }
                                        }
                                    }
                                ],
                                'Compliance': { 
                                    'Status': 'PASSED',
                                    'RelatedRequirements': [
                                        'NIST CSF PR.AC-6',
                                        'NIST SP 800-53 AC-1',
                                        'NIST SP 800-53 AC-2',
                                        'NIST SP 800-53 AC-3',
                                        'NIST SP 800-53 AC-16',
                                        'NIST SP 800-53 AC-19',
                                        'NIST SP 800-53 AC-24',
                                        'NIST SP 800-53 IA-1',
                                        'NIST SP 800-53 IA-2',
                                        'NIST SP 800-53 IA-4',
                                        'NIST SP 800-53 IA-5',
                                        'NIST SP 800-53 IA-8',
                                        'NIST SP 800-53 PE-2',
                                        'NIST SP 800-53 PS-3',
                                        'AICPA TSC CC6.1',
                                        'ISO 27001:2013 A.7.1.1',
                                        'ISO 27001:2013 A.9.2.1'
                                    ]
                                },
                                'Workflow': {
                                    'Status': 'RESOLVED'
                                },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        else:
            pass

def rds_instance_performance_insights_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        perfInsightsCheck = str(dbinstances['PerformanceInsightsEnabled'])
        if perfInsightsCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-perf-insights-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[RDS.6] RDS instances should have performance insights enabled',
                            'Description': 'RDS DB instance ' + instanceId + ' does not have performance insights enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS performance insights and how to configure it refer to the Using Amazon RDS Performance Insights section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.AE-3',
                                    'NIST SP 800-53 AU-6',
                                    'NIST SP 800-53 CA-7',
                                    'NIST SP 800-53 IR-4',
                                    'NIST SP 800-53 IR-5',
                                    'NIST SP 800-53 IR-8', 
                                    'NIST SP 800-53 SI-4',
                                    'AICPA TSC CC7.2',
                                    'ISO 27001:2013 A.12.4.1',
                                    'ISO 27001:2013 A.16.1.7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-perf-insights-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.6] RDS instances should have performance insights enabled',
                            'Description': 'RDS DB instance ' + instanceId + ' has performance insights enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS performance insights and how to configure it refer to the Using Amazon RDS Performance Insights section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.AE-3',
                                    'NIST SP 800-53 AU-6',
                                    'NIST SP 800-53 CA-7',
                                    'NIST SP 800-53 IR-4',
                                    'NIST SP 800-53 IR-5',
                                    'NIST SP 800-53 IR-8', 
                                    'NIST SP 800-53 SI-4',
                                    'AICPA TSC CC7.2',
                                    'ISO 27001:2013 A.12.4.1',
                                    'ISO 27001:2013 A.16.1.7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_deletion_protection_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        deletionProtectionCheck = str(dbinstances['DeletionProtection'])
        if deletionProtectionCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-deletion-prot-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[RDS.7] RDS instances should have deletion protection enabled',
                            'Description': 'RDS DB instance ' + instanceId + ' does not have deletion protection enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS deletion protection and how to configure it refer to the Deletion Protection section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'DeletionProtection': False,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-database-cloudwatch-logs-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.7] RDS instances should have deletion protection enabled',
                            'Description': 'RDS DB instance ' + instanceId + ' has deletion protection enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on RDS deletion protection and how to configure it refer to the Deletion Protection section of the Amazon Relational Database Service User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'DeletionProtection': False,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.BE-5', 
                                    'NIST CSF PR.PT-5',
                                    'NIST SP 800-53 CP-2',
                                    'NIST SP 800-53 CP-11',
                                    'NIST SP 800-53 SA-13',
                                    'NIST SP 800-53 SA14',
                                    'AICPA TSC CC3.1',
                                    'AICPA TSC A1.2',
                                    'ISO 27001:2013 A.11.1.4',
                                    'ISO 27001:2013 A.17.1.1',
                                    'ISO 27001:2013 A.17.1.2',
                                    'ISO 27001:2013 A.17.2.1'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_cloudwatch_logging_check():
    for dbinstances in myRdsInstances:
        instanceArn = str(dbinstances['DBInstanceArn'])
        instanceId = str(dbinstances['DBInstanceIdentifier'])
        instanceClass = str(dbinstances['DBInstanceClass'])
        instancePort = int(dbinstances['Endpoint']['Port'])
        instanceEngine = str(dbinstances['Engine'])
        instanceEngineVersion = str(dbinstances['EngineVersion'])
        try:
            logCheck = str(database['EnabledCloudwatchLogsExports'])
            # this is a passing check
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-database-cloudwatch-logs-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.8] RDS instances should publish database logs to CloudWatch Logs',
                            'Description': 'RDS DB instance ' + instanceId + ' publishes ' + logCheck + ' logs to CloudWatch Logs. Review the types of logs that are published to ensure they fulfill organizational and regulatory requirements as needed.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on database logging with CloudWatch and how to configure it refer to the Publishing Database Logs to Amazon CloudWatch Logs section of the Amazon Relational Database Service User Guide. Aurora does support this but you will need to address another User Guide for information on Aurora database logging with CloudWatch',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html#USER_LogAccess.Procedural.UploadtoCloudWatch'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.AE-3',
                                    'NIST SP 800-53 AU-6',
                                    'NIST SP 800-53 CA-7',
                                    'NIST SP 800-53 IR-4',
                                    'NIST SP 800-53 IR-5',
                                    'NIST SP 800-53 IR-8', 
                                    'NIST SP 800-53 SI-4',
                                    'AICPA TSC CC7.2',
                                    'ISO 27001:2013 A.12.4.1',
                                    'ISO 27001:2013 A.16.1.7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': instanceArn + '/instance-deletion-prot-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[RDS.8] RDS instances should publish database logs to CloudWatch Logs',
                            'Description': 'RDS DB instance ' + instanceId + ' does not publish database logs to CloudWatch Logs. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on database logging with CloudWatch and how to configure it refer to the Publishing Database Logs to Amazon CloudWatch Logs section of the Amazon Relational Database Service User Guide. Aurora does support this but you will need to address another User Guide for information on Aurora database logging with CloudWatch',
                                    'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html#USER_LogAccess.Procedural.UploadtoCloudWatch'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbInstance',
                                    'Id': instanceArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'AwsRdsDbInstance': {
                                            'DBInstanceIdentifier': instanceId,
                                            'DBInstanceClass': instanceClass,
                                            'DbInstancePort': instancePort,
                                            'Engine': instanceEngine,
                                            'EngineVersion': instanceEngineVersion
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.AE-3',
                                    'NIST SP 800-53 AU-6',
                                    'NIST SP 800-53 CA-7',
                                    'NIST SP 800-53 IR-4',
                                    'NIST SP 800-53 IR-5',
                                    'NIST SP 800-53 IR-8', 
                                    'NIST SP 800-53 SI-4',
                                    'AICPA TSC CC7.2',
                                    'ISO 27001:2013 A.12.4.1',
                                    'ISO 27001:2013 A.16.1.7'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_snapshot_encryption_check():
    for snapshot in myRdsSnapshots:
        snapshotId = str(snapshot['DBSnapshotIdentifier'])
        snapshotArn = str(snapshot['DBSnapshotArn'])
        snapshotEncryptionCheck = str(snapshot['Encrypted'])
        if snapshotEncryptionCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': snapshotArn + '/rds-snapshot-encryption-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': snapshotArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[RDS.9] RDS snapshots should be encrypted',
                            'Description': 'RDS snapshot ' + snapshotId + ' is not encrypted. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on encrypting RDS snapshots refer to the AWS Premium Support Knowledge Center Entry How do I encrypt Amazon RDS snapshots?',
                                    'Url': 'https://aws.amazon.com/premiumsupport/knowledge-center/encrypt-rds-snapshots/'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbSnapshot',
                                    'Id': snapshotArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'SnapshotId': snapshotId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.DS-1', 
                                    'NIST SP 800-53 MP-8',
                                    'NIST SP 800-53 SC-12',
                                    'NIST SP 800-53 SC-28',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.2.3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'NEW'
                            },
                            'RecordState': 'ACTIVE'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        else:
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': snapshotArn + '/rds-snapshot-encryption-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': snapshotArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[RDS.9] RDS snapshots should be encrypted',
                            'Description': 'RDS snapshot ' + snapshotId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on encrypting RDS snapshots refer to the AWS Premium Support Knowledge Center Entry How do I encrypt Amazon RDS snapshots?',
                                    'Url': 'https://aws.amazon.com/premiumsupport/knowledge-center/encrypt-rds-snapshots/'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsRdsDbSnapshot',
                                    'Id': snapshotArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'SnapshotId': snapshotId
                                        }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF PR.DS-1', 
                                    'NIST SP 800-53 MP-8',
                                    'NIST SP 800-53 SC-12',
                                    'NIST SP 800-53 SC-28',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.2.3'
                                ]
                            },
                            'Workflow': {
                                'Status': 'RESOLVED'
                            },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_snapshot_public_share_check():
    for snapshot in myRdsSnapshots:
        snapshotId = str(snapshot['DBSnapshotIdentifier'])
        snapshotArn = str(snapshot['DBSnapshotArn'])
        response = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshotId)
        rdsSnapshotAttrs = response['DBSnapshotAttributesResult']['DBSnapshotAttributes']
        for attribute in rdsSnapshotAttrs:
            attrName = str(attribute['AttributeName'])
            if attrName == 'restore':
                attrValue = str(attribute['AttributeValues'])
                if attrValue == "['all']":
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': snapshotArn + '/rds-snapshot-public-share-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': snapshotArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure',
                                        'Sensitive Data Identifications'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'CRITICAL' },
                                    'Confidence': 99,
                                    'Title': '[RDS.10] RDS snapshots should not be publicly shared',
                                    'Description': 'RDS snapshot ' + snapshotId + ' is publicly shared. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on sharing RDS snapshots refer to the Sharing a Snapshot section of the Amazon Relational Database Service User Guide',
                                            'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html#USER_ShareSnapshot.Sharing'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsRdsDbSnapshot',
                                            'Id': snapshotArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': {
                                                    'SnapshotId': snapshotId
                                                }
                                            }
                                        }
                                    ],
                                    'Compliance': { 
                                        'Status': 'FAILED',
                                        'RelatedRequirements': [
                                            'NIST CSF PR.AC-3',
                                            'NIST SP 800-53 AC-1',
                                            'NIST SP 800-53 AC-17',
                                            'NIST SP 800-53 AC-19',
                                            'NIST SP 800-53 AC-20',
                                            'NIST SP 800-53 SC-15',
                                            'AICPA TSC CC6.6',
                                            'ISO 27001:2013 A.6.2.1',
                                            'ISO 27001:2013 A.6.2.2',
                                            'ISO 27001:2013 A.11.2.6',
                                            'ISO 27001:2013 A.13.1.1',
                                            'ISO 27001:2013 A.13.2.1'
                                        ]
                                    },
                                    'Workflow': {
                                        'Status': 'NEW'
                                    },
                                    'RecordState': 'ACTIVE'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                else:
                    try:
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': snapshotArn + '/rds-snapshot-public-share-check',
                                    'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': snapshotArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure',
                                        'Sensitive Data Identifications'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'INFORMATIONAL' },
                                    'Confidence': 99,
                                    'Title': '[RDS.10] RDS snapshots should not be publicly shared',
                                    'Description': 'RDS snapshot ' + snapshotId + ' is not publicly shared.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For more information on sharing RDS snapshots refer to the Sharing a Snapshot section of the Amazon Relational Database Service User Guide',
                                            'Url': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html#USER_ShareSnapshot.Sharing'
                                        }
                                    },
                                    'ProductFields': { 'Product Name': 'ElectricEye' },
                                    'Resources': [
                                        {
                                            'Type': 'AwsRdsDbSnapshot',
                                            'Id': snapshotArn,
                                            'Partition': 'aws-us-gov',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': {
                                                    'SnapshotId': snapshotId
                                                }
                                            }
                                        }
                                    ],
                                    'Compliance': { 
                                        'Status': 'PASSED',
                                        'RelatedRequirements': [
                                            'NIST CSF PR.AC-3',
                                            'NIST SP 800-53 AC-1',
                                            'NIST SP 800-53 AC-17',
                                            'NIST SP 800-53 AC-19',
                                            'NIST SP 800-53 AC-20',
                                            'NIST SP 800-53 SC-15',
                                            'AICPA TSC CC6.6',
                                            'ISO 27001:2013 A.6.2.1',
                                            'ISO 27001:2013 A.6.2.2',
                                            'ISO 27001:2013 A.11.2.6',
                                            'ISO 27001:2013 A.13.1.1',
                                            'ISO 27001:2013 A.13.2.1'
                                        ]
                                    },
                                    'Workflow': {
                                        'Status': 'RESOLVED'
                                    },
                                    'RecordState': 'ARCHIVED'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
            else:
                print('non-supported attribute encountered')
                pass

def rds_instance_auditor():
    rds_instance_ha_check()
    rds_instance_public_access_check()
    rds_instance_storage_encryption_check()
    rds_instance_iam_auth_check()
    rds_instance_domain_join_check()
    rds_instance_performance_insights_check()
    rds_instance_deletion_protection_check()
    rds_instance_cloudwatch_logging_check()
    rds_snapshot_encryption_check()
    rds_snapshot_public_share_check()

rds_instance_auditor()