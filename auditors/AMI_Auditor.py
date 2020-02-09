import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
ec2 = boto3.client('ec2')
sts = boto3.client('sts')
# create account id & region variables
awsAccount = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# find AMIs created by the account
response = ec2.describe_images(Filters=[ { 'Name': 'owner-id','Values': [ awsAccount ] } ],DryRun=False)
myAmis = response['Images']

def public_ami_check():
    for ami in myAmis:
        imageId = str(ami['ImageId'])
        imageName = str(ami['Name'])
        imageCreatedDate = str(ami['CreationDate'])
        publicCheck = str(ami['Public'])
        if publicCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': imageId + '/public-ami',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': imageId,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 90 },
                            'Confidence': 99,
                            'Title': '[AMI.1] Self-managed Amazon Machine Images (AMIs) should not be public',
                            'Description': 'Amazon Machine Image (AMI) ' + imageName + ' is exposed to the public. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': imageId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'AMI Id': imageId, 'AMI CreatedAt': imageCreatedDate }
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
                            'Id': imageId + '/public-ami',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': imageId,
                            'AwsAccountId': awsAccount,
                            'Types': [
                                'Software and Configuration Checks/AWS Security Best Practices',
                                'Effects/Data Exposure'
                            ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[AMI.1] Self-managed Amazon Machine Images (AMIs) should not be public',
                            'Description': 'Amazon Machine Image (AMI) ' + imageName + ' is private.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide',
                                    'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': imageId,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'AMI Id': imageId, 'AMI CreatedAt': imageCreatedDate }
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

def encrypted_ami_check():
    for ami in myAmis:
        imageId = str(ami['ImageId'])
        imageName = str(ami['Name'])
        imageCreatedDate = str(ami['CreationDate'])
        BlockDevices = ami['BlockDeviceMappings']
        for ebsmapping in BlockDevices:
            encryptionCheck = str(ebsmapping['Ebs']['Encrypted'])
            if encryptionCheck == 'False':
                try:
                    # ISO Time
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                    # create Sec Hub finding
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                'SchemaVersion': '2018-10-08',
                                'Id': imageId + '/public-ami',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                                'GeneratorId': imageId,
                                'AwsAccountId': awsAccount,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 80 },
                                'Confidence': 99,
                                'Title': '[AMI.2] Self-managed Amazon Machine Images (AMIs) should be encrypted',
                                'Description': 'Amazon Machine Image (AMI) ' + imageName + ' is not encrypted. Refer to the remediation instructions if this configuration is not intended',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': imageId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'AMI Id': imageId, 'AMI CreatedAt': imageCreatedDate }
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
                                'Id': imageId + '/public-ami',
                                'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                                'GeneratorId': imageId,
                                'AwsAccountId': awsAccount,
                                'Types': [
                                    'Software and Configuration Checks/AWS Security Best Practices',
                                    'Effects/Data Exposure'
                                ],
                                'FirstObservedAt': iso8601Time,
                                'CreatedAt': iso8601Time,
                                'UpdatedAt': iso8601Time,
                                'Severity': { 'Normalized': 0 },
                                'Confidence': 99,
                                'Title': '[AMI.2] Self-managed Amazon Machine Images (AMIs) should be encrypted',
                                'Description': 'Amazon Machine Image (AMI) ' + imageName + ' is encrypted.',
                                'Remediation': {
                                    'Recommendation': {
                                        'Text': 'If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide',
                                        'Url': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy'
                                    }
                                },
                                'ProductFields': {
                                    'Product Name': 'ElectricEye'
                                },
                                'Resources': [
                                    {
                                        'Type': 'Other',
                                        'Id': imageId,
                                        'Partition': 'aws',
                                        'Region': awsRegion,
                                        'Details': {
                                            'Other': { 'AMI Id': imageId, 'AMI CreatedAt': imageCreatedDate }
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

def ami_auditor():
    public_ami_check()
    encrypted_ami_check()

ami_auditor()