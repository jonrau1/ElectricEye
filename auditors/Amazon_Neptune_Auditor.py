import boto3
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
neptune = boto3.client('neptune')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through neptune instances
neptune_instances = neptune.describe_db_instances(Filters=[ { 'Name': 'engine','Values': [ 'neptune' ] } ])

def neptune_instance_multi_az_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        mutliAzCheck = str(instances['MultiAZ'])
        if mutliAzCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-ha-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[Neptune.1] Neptune database instances should be configured to be highly available',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not have Multi-AZ enabled and thus is not highly available. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-ha-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Neptune.1] Neptune database instances should be configured to be highly available',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' is highly available.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune High Availability and how to configure it refer to the High Availability for Neptune section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/feature-overview-availability.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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

def neptune_instance_storage_encryption_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        storageEncryptionCheck = str(instances['StorageEncrypted'])
        if storageEncryptionCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-storage-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.2] Neptune database instace storage should be encrypted',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not have storage encryption enabled. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-storage-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.2] Neptune database instace storage should be encrypted',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' has storage encryption enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune storage encryption and how to configure it refer to the Enabling Encryption for a Neptune DB Instance section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html#encrypt-enable'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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

def neptune_instance_iam_authentication_check():
    for instances in neptune_instances['DBInstances']:
        neptuneInstanceArn = str(instances['DBInstanceArn'])
        neptuneDbId = str(instances['DBInstanceIdentifier'])
        iamDbAuthCheck = str(instances['IAMDatabaseAuthenticationEnabled'])
        if iamDbAuthCheck == 'False':
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': neptuneInstanceArn + '/neptune-instance-iam-db-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Neptune.3] Neptune database instaces storage should use IAM Database Authentication',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' does not use IAM Database Authentication. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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
                            'Id': neptuneInstanceArn + '/neptune-instance-iam-db-auth-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': neptuneInstanceArn,
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
                            'Title': '[Neptune.3] Neptune database instaces storage should use IAM Database Authentication',
                            'Description': 'Neptune database instance ' + neptuneDbId + ' uses IAM Database Authentication.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Neptune IAM Database Authentication and how to configure it refer to the Neptune Database Authentication Using IAM section of the Amazon Neptune User Guide',
                                    'Url': 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': neptuneInstanceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'Neptune Instance ID': neptuneDbId
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

def neptune_auditor():
    neptune_instance_multi_az_check()
    neptune_instance_storage_encryption_check()
    neptune_instance_iam_authentication_check()

neptune_auditor()