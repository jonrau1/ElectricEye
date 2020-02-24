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
import os
import datetime
# import boto3 clients
sts = boto3.client('sts')
workspaces = boto3.client('workspaces')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through workspaces
response = workspaces.describe_workspaces()
myWorkSpaces = response['Workspaces']

def workspaces_user_volume_encryption_check():
    for workspace in myWorkSpaces:
        workspaceId = str(workspace['WorkspaceId'])
        workspaceArn = 'arn:aws:workspaces:' + awsRegion + ':' + awsAccountId + ':workspace/' + workspaceId
        try:
            userVolumeEncryptionCheck = str(workspace['UserVolumeEncryptionEnabled'])
            if userVolumeEncryptionCheck == 'False':
                try:
                    # this is a passed finding
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': workspaceArn + '/workspaces-user-volume-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': workspaceArn,
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
                                'Title': '[WorkSpaces.1] WorkSpaces should have user volume encryption enabled',
                                'Description': 'Workspace ' + workspaceId + ' does not have user volume encryption enabled. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide',
                                        'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': workspaceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'WorkspaceId': workspaceId
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
                    # this is a passed finding
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': workspaceArn + '/workspaces-user-volume-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': workspaceArn,
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
                                'Title': '[WorkSpaces.1] WorkSpaces should have user volume encryption enabled',
                                'Description': 'Workspace ' + workspaceId + ' has user volume encryption enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide',
                                        'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': workspaceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'WorkspaceId': workspaceId
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
        except Exception as e:
            print(e)
        
def workspaces_root_volume_encryption_check():
    for workspace in myWorkSpaces:
        workspaceId = str(workspace['WorkspaceId'])
        workspaceArn = 'arn:aws:workspaces:' + awsRegion + ':' + awsAccountId + ':workspace/' + workspaceId
        try:
            rootVolumeEncryptionCheck = str(workspace['RootVolumeEncryptionEnabled'])
            if rootVolumeEncryptionCheck == 'False':
                try:
                    # this is a passed finding
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': workspaceArn + '/workspaces-root-volume-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': workspaceArn,
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
                                'Title': '[WorkSpaces.1] WorkSpaces should have root volume encryption enabled',
                                'Description': 'Workspace ' + workspaceId + ' does not have root volume encryption enabled. Refer to the remediation instructions to remediate this behavior',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide',
                                        'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': workspaceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'WorkspaceId': workspaceId
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
                    # this is a passed finding
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': workspaceArn + '/workspaces-root-volume-encryption-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': workspaceArn,
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
                                'Title': '[WorkSpaces.1] WorkSpaces should have root volume encryption enabled',
                                'Description': 'Workspace ' + workspaceId + ' does not have root volume encryption enabled.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide',
                                        'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html'
                                    }
                                },
                                'ProductFields': { 'Product Name': 'ElectricEye' },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': workspaceArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': {
                                                'WorkspaceId': workspaceId
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
        except Exception as e:
            print(e)

def workspaces_running_mode_check():
    for workspace in myWorkSpaces:
        workspaceId = str(workspace['WorkspaceId'])
        workspaceArn = 'arn:aws:workspaces:' + awsRegion + ':' + awsAccountId + ':workspace/' + workspaceId
        runningModeCheck = str(workspace['WorkspaceProperties']['RunningMode'])
        if runningModeCheck != 'AUTO_STOP':
            try:
                # this is a passed finding
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': workspaceArn + '/workspaces-auto-stop-running-mode-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': workspaceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[WorkSpaces.3] WorkSpaces should be configured to auto stop after inactivity',
                            'Description': 'Workspace ' + workspaceId + ' does not have its running mode configured to auto-stop. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on WorkSpaces running modes and how to auto-stop refer to the Manage the WorkSpace Running Mode section of the Amazon WorkSpaces Administrator Guide',
                                    'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/running-mode.html#stop-start-workspace'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': workspaceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'WorkspaceId': workspaceId
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
                # this is a passed finding
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': workspaceArn + '/workspaces-auto-stop-running-mode-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': workspaceArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[WorkSpaces.3] WorkSpaces should be configured to auto stop after inactivity',
                            'Description': 'Workspace ' + workspaceId + ' has its running mode configured to auto-stop.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on WorkSpaces running modes and how to auto-stop refer to the Manage the WorkSpace Running Mode section of the Amazon WorkSpaces Administrator Guide',
                                    'Url': 'https://docs.aws.amazon.com/workspaces/latest/adminguide/running-mode.html#stop-start-workspace'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': workspaceArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'WorkspaceId': workspaceId
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

def workspaces_directory_default_internet_check():
    response = workspaces.describe_workspace_directories()
    for directory in response['Directories']:
        workspacesDirectoryId = str(directory['DirectoryId'])
        workspacesDirectoryArn = 'arn:aws:workspaces:' + awsRegion + ':' + awsAccountId + ':directory/' + workspacesDirectoryId
        internetAccessCheck = str(directory['WorkspaceCreationProperties']['EnableInternetAccess'])
        if internetAccessCheck == 'True':
            try:
                # this is a passed finding
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': workspacesDirectoryArn + '/workspaces-directory-default-internet-access-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': workspacesDirectoryArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[WorkSpaces.4] WorkSpaces Directories should not be configured to provide default internet access',
                            'Description': 'Workspace directory ' + workspacesDirectoryId + ' provides default internet access to WorkSpaces. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on WorkSpaces internet access refer to the Provide Internet Access from Your WorkSpace section of the Amazon WorkSpaces Administrator Guide',
                                    'Url': 'https://docs.amazonaws.cn/en_us/workspaces/latest/adminguide/amazon-workspaces-internet-access.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': workspacesDirectoryArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'DirectoryId': workspacesDirectoryId
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
                # this is a passed finding
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': workspacesDirectoryArn + '/workspaces-directory-default-internet-access-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': workspacesDirectoryArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[WorkSpaces.4] WorkSpaces Directories should not be configured to provide default internet access',
                            'Description': 'Workspace directory ' + workspacesDirectoryId + ' does not provide default internet access to WorkSpaces.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on WorkSpaces internet access refer to the Provide Internet Access from Your WorkSpace section of the Amazon WorkSpaces Administrator Guide',
                                    'Url': 'https://docs.amazonaws.cn/en_us/workspaces/latest/adminguide/amazon-workspaces-internet-access.html'
                                }
                            },
                            'ProductFields': { 'Product Name': 'ElectricEye' },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': workspacesDirectoryArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': {
                                            'DirectoryId': workspacesDirectoryId
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

def workspaces_auditor():
    workspaces_user_volume_encryption_check()
    workspaces_root_volume_encryption_check()
    workspaces_running_mode_check()
    workspaces_directory_default_internet_check()

workspaces_auditor()