import boto3
import datetime
import os
# import boto3 clients
sts = boto3.client('sts')
secretsmanager = boto3.client('secretsmanager')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through all secrets
response = secretsmanager.list_secrets(MaxResults=100)
myAsmSecrets = response['SecretList']

def secret_age_check():
    for secrets in myAsmSecrets:
        secretArn = str(secrets['ARN'])
        secretName = str(secrets['Name'])
        lastChangedDate = (secrets['LastChangedDate'])
        todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
        secretAgeFinder = todaysDatetime - lastChangedDate
        if secretAgeFinder >= datetime.timedelta(days=90):
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': secretArn + '/secrets-manager-age-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': secretArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[SecretsManager.1] Secrets over 90 days old should be rotated',
                            'Description': secretName + ' is over 90 days old and should be rotated. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide',
                                    'Url': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': secretArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'Secret Name': secretName }
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
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': secretArn + '/secrets-manager-age-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': secretArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[SecretsManager.1] Secrets over 90 days old should be rotated',
                            'Description': secretName + ' is over 90 days old and should be rotated.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide',
                                    'Url': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': secretArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'Secret Name': secretName }
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

def secret_changed_in_last_90_check():
    for secrets in myAsmSecrets:
        secretArn = str(secrets['ARN'])
        secretName = str(secrets['Name'])
        try:
            rotationCheck = str(secrets['RotationEnabled'])
            print(rotationCheck)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': secretArn + '/secrets-manager-rotation-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': secretArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[SecretsManager.2] Secrets should have automatic rotation configured',
                            'Description': secretName + ' has automatic rotation configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide',
                                    'Url': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': secretArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'Secret Name': secretName }
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
                            'Id': secretArn + '/secrets-manager-rotation-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': secretArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[SecretsManager.2] Secrets should have automatic rotation configured',
                            'Description': secretName + ' does not have automatic rotation configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide',
                                    'Url': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': secretArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'Secret Name': secretName }
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

def secrets_manager_auditor():
    secret_age_check()
    secret_changed_in_last_90_check()

secrets_manager_auditor()