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
                                'Severity': { 'Normalized': 20 },
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
                                            'Other': { 'Volume Id': ebsVolumeId }
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
                                'Severity': { 'Normalized': 0 },
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
                                            'Other': { 'Volume Id': ebsVolumeId }
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
                                'Severity': { 'Normalized': 20 },
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
                                            'Other': { 'Volume Id': ebsVolumeId }
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
                                'Severity': { 'Normalized': 0 },
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
                                            'Other': { 'Volume Id': ebsVolumeId }
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
                            'Severity': { 'Normalized': 80 },
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
                                        'Other': { 'Volume Id': ebsVolumeId }
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
                            'Severity': { 'Normalized': 0 },
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
                                        'Other': { 'Volume Id': ebsVolumeId }
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

def ebs_volume_auditor():
    ebs_volume_attachment_check()
    ebs_volume_delete_on_termination_check()
    ebs_volume_encryption_check()

ebs_volume_auditor()