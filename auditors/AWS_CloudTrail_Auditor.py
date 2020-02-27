import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
cloudtrail = boto3.client('cloudtrail')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through trails
response = cloudtrail.list_trails()
myCloudTrails = response['Trails']

def cloudtrail_multi_region_check():
    for trails in myCloudTrails:
        trailArn = str(trails['TrailARN'])
        trailName = str(trails['Name'])
        response = cloudtrail.describe_trails(trailNameList=[ trailArn ],includeShadowTrails=False)
        for details in response['trailList']:
            multiRegionCheck = str(details['IsMultiRegionTrail'])
            if multiRegionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-multi-region-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 40 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.1] CloudTrail trails should be multi-region',
                                'Description': 'CloudTrail trail ' + trailName + ' is not a multi-region trail. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-multi-region-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.1] CloudTrail trails should be multi-region',
                                'Description': 'CloudTrail trail ' + trailName + ' is a multi-region trail.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should be multi-region refer to the Receiving CloudTrail Log Files from Multiple Regions section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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

def cloudtrail_cloudwatch_logging_check():
    for trails in myCloudTrails:
        trailArn = str(trails['TrailARN'])
        trailName = str(trails['Name'])
        response = cloudtrail.describe_trails(trailNameList=[ trailArn ],includeShadowTrails=False)
        for details in response['trailList']:
            try:
                # this is a passing check
                cloudwatchLogCheck = str(details['CloudWatchLogsLogGroupArn'])
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-cloudwatch-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.2] CloudTrail trails should have CloudWatch logging configured',
                                'Description': 'CloudTrail trail ' + trailName + ' has CloudWatch Logging configured.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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
                if str(e) == "'CloudWatchLogsLogGroupArn'":
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': trailArn + '/cloudtrail-cloudwatch-logging-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': trailArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 40 },
                                    'Confidence': 99,
                                    'Title': '[CloudTrail.2] CloudTrail trails should have CloudWatch logging configured',
                                    'Description': 'CloudTrail trail ' + trailName + ' does not have CloudWatch Logging configured. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your trail should send logs to CloudWatch refer to the Monitoring CloudTrail Log Files with Amazon CloudWatch Logs section of the AWS CloudTrail User Guide',
                                            'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/monitor-cloudtrail-log-files-with-cloudwatch-logs.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsCloudTrailTrail',
                                            'Id': trailArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
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

def cloudtrail_encryption_check():
    for trails in myCloudTrails:
        trailArn = str(trails['TrailARN'])
        trailName = str(trails['Name'])
        response = cloudtrail.describe_trails(trailNameList=[ trailArn ],includeShadowTrails=False)
        for details in response['trailList']:
            try:
                # this is a passing check
                encryptionCheck = str(details['KmsKeyId'])
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-kms-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
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
                                'Title': '[CloudTrail.3] CloudTrail trails should be encrypted by KMS',
                                'Description': 'CloudTrail trail ' + trailName + ' is encrypted by KMS.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS–Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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
                if str(e) == "'KmsKeyId'":
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': trailArn + '/cloudtrail-kms-encryption-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': trailArn,
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
                                    'Title': '[CloudTrail.3] CloudTrail trails should be encrypted by KMS',
                                    'Description': 'CloudTrail trail ' + trailName + ' is not encrypted by KMS. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your trail should be encrypted with SSE-KMS refer to the Encrypting CloudTrail Log Files with AWS KMS–Managed Keys (SSE-KMS) section of the AWS CloudTrail User Guide',
                                            'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsCloudTrailTrail',
                                            'Id': trailArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
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

def cloudtrail_global_services_check():
    for trails in myCloudTrails:
        trailArn = str(trails['TrailARN'])
        trailName = str(trails['Name'])
        response = cloudtrail.describe_trails(trailNameList=[ trailArn ],includeShadowTrails=False)
        for details in response['trailList']:
            globalServiceEventCheck = str(details['IncludeGlobalServiceEvents'])
            if globalServiceEventCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-global-services-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.4] CloudTrail trails should log management events',
                                'Description': 'CloudTrail trail ' + trailName + ' does not log management events. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-global-services-logging-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.4] CloudTrail trails should log management events',
                                'Description': 'CloudTrail trail ' + trailName + ' logs management events.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should log management events refer to the Management Events section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#logging-management-events'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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

def cloudtrail_log_file_validation_check():
    for trails in myCloudTrails:
        trailArn = str(trails['TrailARN'])
        trailName = str(trails['Name'])
        response = cloudtrail.describe_trails(trailNameList=[ trailArn ],includeShadowTrails=False)
        for details in response['trailList']:
            fileValidationCheck = str(details['LogFileValidationEnabled'])
            if fileValidationCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-log-file-validation-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 20 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.5] CloudTrail log file validation should be enabled',
                                'Description': 'CloudTrail trail ' + trailName + ' does not log management events. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': trailArn + '/cloudtrail-log-file-validation-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': trailArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[CloudTrail.5] CloudTrail log file validation should be enabled',
                                'Description': 'CloudTrail trail ' + trailName + ' does not log management events. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your trail should have log file validation enabled refer to the Validating CloudTrail Log File Integrity section of the AWS CloudTrail User Guide',
                                        'Url': 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsCloudTrailTrail',
                                        'Id': trailArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
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

def cloudtrail_auditor():
    cloudtrail_multi_region_check()
    cloudtrail_cloudwatch_logging_check()
    cloudtrail_encryption_check()
    cloudtrail_global_services_check()
    cloudtrail_log_file_validation_check()

cloudtrail_auditor()