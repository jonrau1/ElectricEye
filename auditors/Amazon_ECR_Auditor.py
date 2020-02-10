import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
ecr = boto3.client('ecr')
sts = boto3.client('sts')
# create account id & region variables
awsAccount = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through ECR repos
response = ecr.describe_repositories(maxResults=1000)
myRepos = response['repositories']
for repo in myRepos:
    repoArn = str(repo['repositoryArn'])
    repoName = str(repo['repositoryName'])
    scanningConfig = str(repo['imageScanningConfiguration']['scanOnPush'])
    if scanningConfig == 'False':
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': repoArn + '/ecr-no-scan',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                        'GeneratorId': repoArn,
                        'AwsAccountId': awsAccount,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 40 },
                        'Confidence': 99,
                        'Title': '[ECR.1] Elastic Container Registry repositories should be configured to scan images on push',
                        'Description': 'Elastic Container Registry repository ' + repoName + ' is not configured to scan images on push. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If your repository should be configured to scan on push refer to Image Scanning in the Amazon ECR User Guide',
                                'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'Other',
                                'Id': repoArn,
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'Repository Name': repoName }
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
                        'Id': repoArn + '/ecr-no-scan',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                        'GeneratorId': repoArn,
                        'AwsAccountId': awsAccount,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Normalized': 0 },
                        'Confidence': 99,
                        'Title': '[ECR.1] Elastic Container Registry repositories should be configured to scan images on push',
                        'Description': 'Elastic Container Registry repository ' + repoName + ' is configured to scan images on push.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'If your repository should be configured to scan on push refer to Image Scanning in the Amazon ECR User Guide',
                                'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
                            }
                        },
                        'ProductFields': {
                            'Product Name': 'ElectricEye'
                        },
                        'Resources': [
                            {
                                'Type': 'Other',
                                'Id': repoArn,
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Other': { 'Repository Name': repoName }
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