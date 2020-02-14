import boto3
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
s3 = boto3.client('s3')
s3control = boto3.client('s3control')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through s3 buckets
response = s3.list_buckets()
myS3Buckets = response['Buckets']

def bucket_encryption_check():
    for buckets in myS3Buckets:
        bucketName = str(buckets['Name'])
        s3Arn = 'arn:aws:s3:::' + bucketName
        try:
            response = s3.get_bucket_encryption(Bucket=bucketName)
            for rules in response['ServerSideEncryptionConfiguration']['Rules']:
                sseType = str(rules['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'])
                # this is a passing check
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': s3Arn + '/s3-bucket-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': s3Arn,
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
                                'Title': '[S3.1] S3 Buckets should be encrypted',
                                'Description': 'S3 bucket ' + bucketName + ' is encrypted using ' + sseType + '.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsS3Bucket',
                                        'Id': s3Arn,
                                        'Partition': 'aws',
                                        'Region': awsRegion
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
        except Exception as e:
            if str(e) == 'An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption operation: The server side encryption configuration was not found':
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': s3Arn + '/s3-bucket-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': s3Arn,
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
                                'Title': '[S3.1] S3 Buckets should be encrypted',
                                'Description': 'S3 bucket ' + bucketName + ' is not encrypted. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsS3Bucket',
                                        'Id': s3Arn,
                                        'Partition': 'aws',
                                        'Region': awsRegion
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
                print(e)

def bucket_lifecycle_check():
    for buckets in myS3Buckets:
        bucketName = str(buckets['Name'])
        s3Arn = 'arn:aws:s3:::' + bucketName
        try:
            response = s3.get_bucket_lifecycle_configuration(Bucket=bucketName)
            # this is a passing check
            try:
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': s3Arn + '/s3-bucket-lifecyle-configuration-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': s3Arn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations',
                            'Description': 'S3 bucket ' + bucketName + ' has a lifecycle policy configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Lifecycle policies and how to configure it refer to the How Do I Create a Lifecycle Policy for an S3 Bucket? section of the Amazon Simple Storage Service Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-lifecycle.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'AwsS3Bucket',
                                    'Id': s3Arn,
                                    'Partition': 'aws',
                                    'Region': awsRegion
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
        except Exception as e:
            if str(e) == 'An error occurred (NoSuchLifecycleConfiguration) when calling the GetBucketLifecycleConfiguration operation: The lifecycle configuration does not exist':
                try:
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': s3Arn + '/s3-bucket-lifecyle-configuration-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': s3Arn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations',
                                'Description': 'S3 bucket ' + bucketName + ' does not have a lifecycle policy configured. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on Lifecycle policies and how to configure it refer to the How Do I Create a Lifecycle Policy for an S3 Bucket? section of the Amazon Simple Storage Service Developer Guide',
                                        'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-lifecycle.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'AwsS3Bucket',
                                        'Id': s3Arn,
                                        'Partition': 'aws',
                                        'Region': awsRegion
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
                print(e)

def s3_account_level_block():
    response = s3control.get_public_access_block(AccountId=awsAccountId)
    accountBlock = response['PublicAccessBlockConfiguration']
    blockAcl = str(accountBlock['BlockPublicAcls'])
    ignoreAcl = str(accountBlock['IgnorePublicAcls'])
    blockPubPolicy = str(accountBlock['BlockPublicPolicy'])
    restrictPubBuckets = str(accountBlock['RestrictPublicBuckets'])
    if blockAcl and ignoreAcl and blockPubPolicy and restrictPubBuckets == 'True':
        try:
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/s3-account-level-public-access-block-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': awsAccountId,
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
                        'Title': '[S3.3] Account-level S3 public access block should be configured',
                        'Description': 'Account-level S3 public access block for account ' + awsAccountId + ' is enabled',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html'
                            }
                        },
                        'ProductFields': { 'Product Name': 'ElectricEye' },
                        'Resources': [
                            {
                                'Type': 'AwsAccount',
                                'Id': 'AWS::::Account:' + awsAccountId,
                                'Partition': 'aws',
                                'Region': awsRegion
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
        try:
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/s3-account-level-public-access-block-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': awsAccountId,
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
                        'Title': '[S3.3] Account-level S3 public access block should be configured',
                        'Description': 'Account-level S3 public access block for account ' + awsAccountId + ' is either inactive or is not block all possible scenarios. Refer to the remediation instructions to remediate this behavior',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide',
                                'Url': 'https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html'
                            }
                        },
                        'ProductFields': { 'Product Name': 'ElectricEye' },
                        'Resources': [
                            {
                                'Type': 'AwsAccount',
                                'Id': 'AWS::::Account:' + awsAccountId,
                                'Partition': 'aws',
                                'Region': awsRegion
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

def s3_bucket_auditor():
    bucket_encryption_check()
    bucket_lifecycle_check()
    s3_account_level_block()

s3_bucket_auditor()