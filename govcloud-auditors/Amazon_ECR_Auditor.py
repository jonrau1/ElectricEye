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
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.CM-8',
                                    'NIST SP 800-53 RA-5',
                                    'AICPA TSC CC7.1',
                                    'ISO 27001:2013 A.12.6.1'
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
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': repoArn + '/ecr-no-scan',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF DE.CM-8',
                                    'NIST SP 800-53 RA-5',
                                    'AICPA TSC CC7.1',
                                    'ISO 27001:2013 A.12.6.1'
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
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'PASSED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.AM-2',
                                    'NIST SP 800-53 CM-8',
                                    'NIST SP 800-53 PM-5',
                                    'AICPA TSC CC3.2',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.1.1',
                                    'ISO 27001:2013 A.8.1.2',
                                    'ISO 27001:2013 A.12.5.1'
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
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': repoArn + '/ecr-lifecycle-policy-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
                                    }
                                }
                            ],
                            'Compliance': { 
                                'Status': 'FAILED',
                                'RelatedRequirements': [
                                    'NIST CSF ID.AM-2',
                                    'NIST SP 800-53 CM-8',
                                    'NIST SP 800-53 PM-5',
                                    'AICPA TSC CC3.2',
                                    'AICPA TSC CC6.1',
                                    'ISO 27001:2013 A.8.1.1',
                                    'ISO 27001:2013 A.8.1.2',
                                    'ISO 27001:2013 A.12.5.1'
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
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': repoArn,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'MEDIUM' },
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
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'RepositoryName': repoName }
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

def ecr_latest_image_vuln_check():
    for repo in myRepos:
        repoArn = str(repo['repositoryArn'])
        repoName = str(repo['repositoryName'])
        scanningConfig = str(repo['imageScanningConfiguration']['scanOnPush'])
        if scanningConfig == 'True':
            try:
                response = ecr.describe_images(repositoryName=repoName,filter={'tagStatus':'TAGGED'},maxResults=1000)
                for images in response['imageDetails']:
                    imageDigest = str(images['imageDigest'])
                    # use the first tag only as we need it to create the canonical ID for the Resource.Id in the ASFF for the Container Resource.Type
                    imageTag = str(images['imageTags'][0])
                    imageVulnCheck = str(images['imageScanFindingsSummary']['findingSeverityCounts'])
                    if imageVulnCheck != '{}':
                        vulnDeepLink = 'https://console.aws.amazon.com/ecr/repositories/' + repoName + '/image/' + imageDigest + '/scan-results?region=' + awsRegion
                        try:
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': repoName + '/' + imageDigest + '/ecr-latest-image-vuln-check',
                                        'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                                        'GeneratorId': imageDigest,
                                        'AwsAccountId': awsAccount,
                                        'Types': [ 
                                            'Software and Configuration Checks/Vulnerabilities/CVE',
                                            'Software and Configuration Checks/AWS Security Best Practices' 
                                        ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'MEDIUM' },
                                        'Confidence': 99,
                                        'Title': '[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities',
                                        'Description': 'The latest image in the ECR repository ' + repoName + ' has the following vulnerabilities reported: ' + imageVulnCheck + '. Refer to the SourceUrl or Remediation.Recommendation.Url to review the specific vulnerabilities and remediation information from ECR.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'Click here to navigate to the ECR Vulnerability console for this image',
                                                'Url': vulnDeepLink
                                            }
                                        },
                                        'SourceUrl': vulnDeepLink,
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Container',
                                                'Id': repoName + ':' + imageTag,
                                                'Partition': 'aws-us-gov',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Container': {
                                                        'Name': repoName + ':' + imageTag,
                                                        'ImageId': imageDigest
                                                    },
                                                    'Other': {
                                                        'RepositoryName': repoName,
                                                        'RepositoryArn': repoArn
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'FAILED',
                                            'RelatedRequirements': [
                                                'NIST CSF DE.CM-8',
                                                'NIST SP 800-53 RA-5',
                                                'AICPA TSC CC7.1',
                                                'ISO 27001:2013 A.12.6.1'
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
                            # ISO Time
                            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                            # create Sec Hub finding
                            response = securityhub.batch_import_findings(
                                Findings=[
                                    {
                                        'SchemaVersion': '2018-10-08',
                                        'Id': repoName + '/' + imageDigest + '/ecr-latest-image-vuln-check',
                                        'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                                        'GeneratorId': imageDigest,
                                        'AwsAccountId': awsAccount,
                                        'Types': [ 
                                            'Software and Configuration Checks/Vulnerabilities/CVE',
                                            'Software and Configuration Checks/AWS Security Best Practices' 
                                        ],
                                        'FirstObservedAt': iso8601Time,
                                        'CreatedAt': iso8601Time,
                                        'UpdatedAt': iso8601Time,
                                        'Severity': { 'Label': 'INFORMATIONAL' },
                                        'Confidence': 99,
                                        'Title': '[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities',
                                        'Description': 'The latest image in the ECR repository ' + repoName + ' does not have any vulnerabilities reported.',
                                        'Remediation': {
                                            'Recommendation': {
                                                'Text': 'Click here to navigate to the ECR Vulnerability console for this image',
                                                'Url': vulnDeepLink
                                            }
                                        },
                                        'SourceUrl': vulnDeepLink,
                                        'ProductFields': {
                                            'Product Name': 'ElectricEye'
                                        },
                                        'Resources': [
                                            {
                                                'Type': 'Container',
                                                'Id': repoName + ':' + imageTag,
                                                'Partition': 'aws-us-gov',
                                                'Region': awsRegion,
                                                'Details': {
                                                    'Container': {
                                                        'Name': repoName + ':' + imageTag,
                                                        'ImageId': imageDigest
                                                    },
                                                    'Other': {
                                                        'RepositoryName': repoName,
                                                        'RepositoryArn': repoArn
                                                    }
                                                }
                                            }
                                        ],
                                        'Compliance': { 
                                            'Status': 'PASSED',
                                            'RelatedRequirements': [
                                                'NIST CSF DE.CM-8',
                                                'NIST SP 800-53 RA-5',
                                                'AICPA TSC CC7.1',
                                                'ISO 27001:2013 A.12.6.1'
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
            except Exception as e:
                print(e)
        else:
            pass

def ecr_auditor():
    ecr_repo_vuln_scan_check()
    ecr_repo_image_lifecycle_policy_check()
    ecr_repo_permission_policy()
    ecr_latest_image_vuln_check()

ecr_auditor()