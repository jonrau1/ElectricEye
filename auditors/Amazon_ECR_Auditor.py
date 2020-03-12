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

def ecr_repo_vuln_scan_check():
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
                            'Title': '[ECR.1] ECR repositories should be configured to scan images on push',
                            'Description': 'ECR repository ' + repoName + ' is not configured to scan images on push. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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
                            'Title': '[ECR.1] ECR repositories should be configured to scan images on push',
                            'Description': 'ECR repository ' + repoName + ' is configured to scan images on push.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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

def ecr_repo_image_lifecycle_policy_check():
    for repo in myRepos:
        repoArn = str(repo['repositoryArn'])
        repoName = str(repo['repositoryName'])
        try:
            # this is a passing finding
            response = ecr.get_lifecycle_policy(repositoryName=repoName)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': repoArn + '/ecr-lifecycle-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[ECR.2] ECR repositories should be have an image lifecycle policy configured',
                            'Description': 'ECR repository ' + repoName + ' does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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
                            'Id': repoArn + '/ecr-lifecycle-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[ECR.2] ECR repositories should be have an image lifecycle policy configured',
                            'Description': 'ECR repository ' + repoName + ' does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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

def ecr_repo_permission_policy():
    for repo in myRepos:
        repoArn = str(repo['repositoryArn'])
        repoName = str(repo['repositoryName'])
        try:
            # this is a passing finding
            response = ecr.get_repository_policy(repositoryName=repoName)
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': repoArn + '/ecr-repo-access-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[ECR.3] ECR repositories should be have a repository policy configured',
                            'Description': 'ECR repository ' + repoName + ' has a repository policy configured.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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
                            'Id': repoArn + '/ecr-repo-access-policy-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[ECR.3] ECR repositories should be have a repository policy configured',
                            'Description': 'ECR repository ' + repoName + ' does not have a repository policy configured. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEcrRepository',
                                    'Id': repoArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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

def ecr_auditor():
    ecr_repo_vuln_scan_check()
    ecr_repo_image_lifecycle_policy_check()
    ecr_repo_permission_policy()

ecr_auditor()