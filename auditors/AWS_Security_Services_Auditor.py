import boto3
import uuid
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
accessanalyzer = boto3.client('accessanalyzer')
guardduty = boto3.client('guardduty')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']

def iam_access_analyzer_detector_check():
    response = accessanalyzer.list_analyzers()
    iamAccessAnalyzerCheck = str(response['analyzers'])
    if iamAccessAnalyzerCheck == '[]':
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # unique ID
            generatorUuid = str(uuid.uuid4())
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/security-services-iaa-enabled-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': generatorUuid,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 60 },
                        'Confidence': 99,
                        'Title': '[SecSvcs.1] IAM Access Analyzer should be enabled',
                        'Description': 'IAM Access Analyzer is not enabled. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide',
                                'Url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
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
    else:
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # unique ID
            generatorUuid = str(uuid.uuid4())
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/security-services-iaa-enabled-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': generatorUuid,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 0 },
                        'Confidence': 99,
                        'Title': '[SecSvcs.1] IAM Access Analyzer should be enabled',
                        'Description': 'IAM Access Analyzer is enabled.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide',
                                'Url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
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

def guardduty_detector_check():
    response = guardduty.list_detectors()
    guarddutyDetectorCheck = str(response['DetectorIds'])
    if guarddutyDetectorCheck == '[]':
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # unique ID
            generatorUuid = str(uuid.uuid4())
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/security-services-guardduty-enabled-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': generatorUuid,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 60 },
                        'Confidence': 99,
                        'Title': '[SecSvcs.2] GuardDuty should be enabled',
                        'Description': 'GuardDuty is not enabled. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide',
                                'Url': 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
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
    else:
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # unique ID
            generatorUuid = str(uuid.uuid4())
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + '/security-services-guardduty-enabled-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': generatorUuid,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 0 },
                        'Confidence': 99,
                        'Title': '[SecSvcs.2] GuardDuty should be enabled',
                        'Description': 'GuardDuty is not enabled. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide',
                                'Url': 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
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

def security_services_auditor():
    iam_access_analyzer_detector_check()
    guardduty_detector_check()

security_services_auditor()