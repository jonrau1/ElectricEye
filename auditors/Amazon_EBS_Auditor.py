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
ec2 = boto3.client('ec2')
securityhub = boto3.client('securityhub')
# create env vars
awsRegion = os.environ['AWS_REGION']
awsAccountId = sts.get_caller_identity()['Account']
# loop through EBS volumes
response = ec2.describe_volumes(DryRun=False,MaxResults=500)
myEbsVolumes = response['Volumes']
# loop through EBS snapshots
response = ec2.describe_snapshots(OwnerIds=[ awsAccountId ],DryRun=False)
myEbsSnapshots = response['Snapshots']

def ebs_volume_attachment_check():
    for volumes in myEbsVolumes:
        ebsVolumeId = str(volumes['VolumeId'])
        ebsVolumeArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + '/' + ebsVolumeId
        ebsAttachments = volumes['Attachments']
        for attachments in ebsAttachments:
            ebsAttachmentState = str(attachments['State'])
            if ebsAttachmentState != 'attached':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': ebsVolumeArn + '/ebs-volume-attachment-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': ebsVolumeArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[EBS.1] EBS Volumes should be in an attached state',
                                'Description': 'EBS Volume ' + ebsVolumeId + ' is not in an attached state. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Volume',
                                        'Id': ebsVolumeArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'VolumeId': ebsVolumeId }
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
                                'Id': ebsVolumeArn + '/ebs-volume-attachment-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': ebsVolumeArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[EBS.1] EBS Volumes should be in an attached state',
                                'Description': 'EBS Volume ' + ebsVolumeId + ' is in an attached state.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Volume',
                                        'Id': ebsVolumeArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'VolumeId': ebsVolumeId }
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

def ebs_volume_delete_on_termination_check():
    for volumes in myEbsVolumes:
        ebsVolumeId = str(volumes['VolumeId'])
        ebsVolumeArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + '/' + ebsVolumeId
        ebsAttachments = volumes['Attachments']
        for attachments in ebsAttachments:
            ebsDeleteOnTerminationCheck = str(attachments['DeleteOnTermination'])
            if ebsDeleteOnTerminationCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': ebsVolumeArn + '/ebs-volume-delete-on-termination-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': ebsVolumeArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'LOW' },
                                'Confidence': 99,
                                'Title': '[EBS.2] EBS Volumes should be configured to be deleted on termination',
                                'Description': 'EBS Volume ' + ebsVolumeId + ' is not configured to be deleted on termination. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EBS volume should be deleted on instance termination refer to the Preserving Amazon EBS Volumes on Instance Termination section of the Amazon Elastic Compute Cloud User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#preserving-volumes-on-termination'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Volume',
                                        'Id': ebsVolumeArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'VolumeId': ebsVolumeId }
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
                                'Id': ebsVolumeArn + '/ebs-volume-delete-on-termination-check',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                'GeneratorId': ebsVolumeArn,
                                'AwsAccountId': awsAccountId,
                                'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Label': 'INFORMATIONAL' },
                                'Confidence': 99,
                                'Title': '[EBS.2] EBS Volumes should be configured to be deleted on termination',
                                'Description': 'EBS Volume ' + ebsVolumeId + ' is configured to be deleted on termination.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your EBS volume should be deleted on instance termination refer to the Preserving Amazon EBS Volumes on Instance Termination section of the Amazon Elastic Compute Cloud User Guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#preserving-volumes-on-termination'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'AwsEc2Volume',
                                        'Id': ebsVolumeArn,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'VolumeId': ebsVolumeId }
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

def ebs_volume_encryption_check():
    for volumes in myEbsVolumes:
        ebsVolumeId = str(volumes['VolumeId'])
        ebsVolumeArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + '/' + ebsVolumeId
        ebsEncryptionCheck = str(volumes['Encrypted'])
        if ebsEncryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': ebsVolumeArn + '/ebs-volume-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': ebsVolumeArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[EBS.3] EBS Volumes should be encrypted',
                            'Description': 'EBS Volume ' + ebsVolumeId + ' is not encrypted. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your EBS volume should be encrypted refer to the Amazon EBS Encryption section of the Amazon Elastic Compute Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Volume',
                                    'Id': ebsVolumeArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'VolumeId': ebsVolumeId }
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
                            'Id': ebsVolumeArn + '/ebs-volume-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': ebsVolumeArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EBS.3] EBS Volumes should be encrypted',
                            'Description': 'EBS Volume ' + ebsVolumeId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your EBS volume should be encrypted refer to the Amazon EBS Encryption section of the Amazon Elastic Compute Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Volume',
                                    'Id': ebsVolumeArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'VolumeId': ebsVolumeId }
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

def ebs_snapshot_encryption_check():
    for snapshots in myEbsSnapshots:
        snapshotId = str(snapshots['SnapshotId'])
        snapshotArn = 'arn:aws:ec2:' + awsRegion + '::snapshot/' + snapshotId
        snapshotEncryptionCheck = str(snapshots['Encrypted'])
        if snapshotEncryptionCheck == 'False':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': snapshotArn + '/ebs-snapshot-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': snapshotArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'HIGH' },
                            'Confidence': 99,
                            'Title': '[EBS.4] EBS Snapshots should be encrypted',
                            'Description': 'EBS Snapshot ' + snapshotId + ' is not encrypted. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your EBS snapshot should be encrypted refer to the Encryption Support for Snapshots section of the Amazon Elastic Compute Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/EBSSnapshots.html#encryption-support'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Snapshot',
                                    'Id': snapshotArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'SnapshotId': snapshotId }
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
                            'Id': snapshotArn + '/ebs-snapshot-encryption-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': snapshotArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EBS.4] EBS Snapshots should be encrypted',
                            'Description': 'EBS Snapshot ' + snapshotId + ' is encrypted.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your EBS snapshot should be encrypted refer to the Encryption Support for Snapshots section of the Amazon Elastic Compute Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/EBSSnapshots.html#encryption-support'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Snapshot',
                                    'Id': snapshotArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'SnapshotId': snapshotId }
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

def ebs_snapshot_public_check():
    for snapshots in myEbsSnapshots:
        snapshotId = str(snapshots['SnapshotId'])
        snapshotArn = 'arn:aws:ec2:' + awsRegion + '::snapshot/' + snapshotId
        response = ec2.describe_snapshot_attribute(Attribute='createVolumePermission',SnapshotId=snapshotId,DryRun=False)
        if str(response['CreateVolumePermissions']) == '[]':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': snapshotArn + '/ebs-snapshot-public-share-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': snapshotArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Label': 'INFORMATIONAL' },
                            'Confidence': 99,
                            'Title': '[EBS.5] EBS Snapshots should not be public',
                            'Description': 'EBS Snapshot ' + snapshotId + ' is private.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Snapshot',
                                    'Id': snapshotArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'SnapshotId': snapshotId }
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
        else:
            for permissions in response['CreateVolumePermissions']:
                # {'Group': 'all'} denotes public
                # you should still audit accounts you have shared
                if str(permissions) == "{'Group': 'all'}":
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': snapshotArn + '/ebs-snapshot-public-share-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': snapshotArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'CRITICAL' },
                                    'Confidence': 99,
                                    'Title': '[EBS.5] EBS Snapshots should not be public',
                                    'Description': 'EBS Snapshot ' + snapshotId + ' is public. Refer to the remediation instructions to remediate this behavior',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Snapshot',
                                            'Id': snapshotArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'SnapshotId': snapshotId }
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
                                    'Id': snapshotArn + '/ebs-snapshot-public-share-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': snapshotArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 
                                        'Software and Configuration Checks/AWS Security Best Practices',
                                        'Effects/Data Exposure'
                                    ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Label': 'INFORMATIONAL' },
                                    'Confidence': 99,
                                    'Title': '[EBS.5] EBS Snapshots should not be public',
                                    'Description': 'EBS Snapshot ' + snapshotId + ' is private, however, this snapshot has been identified as being shared with other accounts. You should audit these accounts to ensure they are still authorized to have this snapshot shared with them.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide',
                                            'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Snapshot',
                                            'Id': snapshotArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'Other': { 'SnapshotId': snapshotId }
                                            }
                                        }
                                    ],
                                    'Compliance': { 'Status': 'PASSED' },
                                    'RecordState': 'ACTIVE'
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)

def ebs_account_encryption_by_default_check():
    response = ec2.get_ebs_encryption_by_default(DryRun=False)
    if str(response['EbsEncryptionByDefault']) == 'False':
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + awsRegion + '/ebs-account-encryption-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': awsAccountId + '/' + awsRegion,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'MEDIUM' },
                        'Confidence': 99,
                        'Title': '[EBS.6] Account-level EBS Volume encryption should be enabled',
                        'Description': 'Account-level EBS volume encryption is not enabled for AWS Account ' + awsAccountId + ' in ' + awsRegion + '. Refer to the remediation instructions if this configuration is not intended',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For information on Account-level encryption refer to the Encryption by Default to an Instance section of the Amazon Elastic Compute Cloud User Guide',
                                'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default'
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
            # create Sec Hub finding
            response = securityhub.batch_import_findings(
                Findings=[
                    {
                        'SchemaVersion': '2018-10-08',
                        'Id': awsAccountId + awsRegion + '/ebs-account-encryption-check',
                        'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                        'GeneratorId': awsAccountId + '/' + awsRegion,
                        'AwsAccountId': awsAccountId,
                        'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                        'FirstObservedAt': iso8601Time,
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': { 'Label': 'INFORMATIONAL' },
                        'Confidence': 99,
                        'Title': '[EBS.6] Account-level EBS Volume encryption should be enabled',
                        'Description': 'Account-level EBS volume encryption is enabled for AWS Account ' + awsAccountId + ' in ' + awsRegion + '.',
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'For information on Account-level encryption refer to the Encryption by Default to an Instance section of the Amazon Elastic Compute Cloud User Guide',
                                'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default'
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

def ebs_volume_auditor():
    ebs_volume_attachment_check()
    ebs_volume_delete_on_termination_check()
    ebs_volume_encryption_check()
    ebs_snapshot_encryption_check()
    ebs_snapshot_public_check()
    ebs_account_encryption_by_default_check()

ebs_volume_auditor()