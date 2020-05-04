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
ds = boto3.client('ds')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through Directory Service directories
# not to be confused with weird ass cloud directory
response = ds.describe_directories()
myDirectories = response['DirectoryDescriptions']

def directory_service_radius_check():
    for directory in myDirectories:
        directoryId = str(directory['DirectoryId'])
        directoryArn = 'arn:aws-us-gov:ds:' + awsRegion + ':' + awsAccountId + ':directory/' + directoryId
        directoryName = str(directory['Name'])
        directoryType = str(directory['Type'])
        if directoryType != 'SimpleAD':
            try:
                # this is a passing check
                radiusCheck = str(directory['RadiusSettings'])
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': directoryArn + '/directory-service-radius-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': directoryArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)',
                                'Description': 'Directory ' + directoryName + ' has RADIUS enabled and likely supports MFA.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide',
                                        'Url': 'https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': directoryArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'directoryName': directoryName }
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
                                'Id': directoryArn + '/directory-service-radius-check',
                                'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': directoryArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'HIGH' },
                                'Confidence': 99,
                                'Title': '[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)',
                                'Description': 'Directory ' + directoryName + ' does not have RADIUS enabled and thus does not support MFA. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide',
                                        'Url': 'https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': directoryArn,
                                        'Partition': 'aws-us-gov',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'directoryName': directoryName }
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
            print('SimpleAD does not support RADIUS, skipping')
            pass

def directory_service_cloudwatch_logs_check():
    for directory in myDirectories:
        directoryId = str(directory['DirectoryId'])
        directoryArn = 'arn:aws-us-gov:ds:' + awsRegion + ':' + awsAccountId + ':directory/' + directoryId
        directoryName = str(directory['Name'])
        response = ds.list_log_subscriptions(DirectoryId=directoryId)
        if str(response['LogSubscriptions']) == '[]':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': directoryArn + '/directory-service-cloudwatch-logs-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': directoryArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'LOW' },
                            'Confidence': 99,
                            'Title': '[DirectoryService.2] Directories should have log forwarding enabled',
                            'Description': 'Directory ' + directoryName + ' does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': directoryArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'directoryName': directoryName }
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
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': directoryArn + '/directory-service-cloudwatch-logs-check',
                            'ProductArn': 'arn:aws-us-gov:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': directoryArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[DirectoryService.2] Directories should have log forwarding enabled',
                            'Description': 'Directory ' + directoryName + ' does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide',
                                    'Url': 'https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': directoryArn,
                                    'Partition': 'aws-us-gov',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'directoryName': directoryName }
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

def directory_service_auditor():
    directory_service_radius_check()
    directory_service_cloudwatch_logs_check()

directory_service_auditor()