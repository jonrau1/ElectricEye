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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'FAILED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'PASSED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'FAILED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'PASSED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'FAILED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'PASSED' },
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
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 50 },
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
                                        'Partition': 'aws',
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
                                'Compliance': { 'Status': 'FAILED' },
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
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
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
                                        'Partition': 'aws',
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
                                'Compliance': { 'Status': 'PASSED' },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        else:
            print('This DB does not support IAM auth')
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
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 50 },
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
                                        'Partition': 'aws',
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
                                'Compliance': { 'Status': 'FAILED' },
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
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': instanceArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
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
                                        'Partition': 'aws',
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
                                'Compliance': { 'Status': 'PASSED', },
                                'RecordState': 'ARCHIVED'
                            }
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
        else:
            print('This DB does not support Kerberos auth')
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'FAILED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'PASSED' },
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
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'FAILED' },
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
                            'Id': instanceArn + '/instance-deletion-prot-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': instanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
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
                                    'Partition': 'aws',
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
                            'Compliance': { 'Status': 'PASSED' },
                            'RecordState': 'ARCHIVED'
                        }
                    ]
                )
                print(response)
            except Exception as e:
                print(e)

def rds_instance_auditor():
    rds_instance_ha_check()
    rds_instance_public_access_check()
    rds_instance_storage_encryption_check()
    rds_instance_iam_auth_check()
    rds_instance_domain_join_check()
    rds_instance_performance_insights_check()
    rds_instance_deletion_protection_check()

rds_instance_auditor()