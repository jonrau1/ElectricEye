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
efs = boto3.client('efs')
sts = boto3.client('sts')
# create account id & region variables
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through EFS file systems
response = efs.describe_file_systems()
myFileSys = response['FileSystems']

def efs_filesys_encryption_check():
    for filesys in myFileSys:
        encryptionCheck = str(filesys['Encrypted'])
        fileSysId = str(filesys['FileSystemId'])
        fileSysArn = 'arn:aws:elasticfilesystem:' + awsRegion + ':' + awsAccountId + ':file-system/' + fileSysId
        if encryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fileSysArn + '/efs-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': fileSysArn,
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
                            'Title': '[EFS.1] EFS File Systems should have encryption enabled',
                            'Description': 'EFS file system ' + fileSysId + '  does not have encryption enabled. EFS file systems cannot be encrypted after creation, consider backing up data and creating a new encrypted file system.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For EFS encryption information refer to the Data Encryption in EFS section of the Amazon Elastic File System User Guide',
                                    'Url': 'https://docs.aws.amazon.com/efs/latest/ug/encryption.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': fileSysArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'FileSystemId': fileSysId
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
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': fileSysArn + '/efs-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': fileSysArn,
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
                            'Title': '[EFS.1] EFS File Systems should have encryption enabled',
                            'Description': 'EFS file system ' + fileSysId + '  has encryption enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For EFS encryption information refer to the Data Encryption in EFS section of the Amazon Elastic File System User Guide',
                                    'Url': 'https://docs.aws.amazon.com/efs/latest/ug/encryption.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': fileSysArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 
                                            'FileSystemId': fileSysId
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

def efs_auditor():
    efs_filesys_encryption_check()

efs_auditor()