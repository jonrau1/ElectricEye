import boto3
import datetime
import os
# create boto3 clients
sts = boto3.client('sts')
ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')
securityhub = boto3.client('securityhub')
# create env vars
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
# loop through ec2 instances
response = ec2.describe_instances(DryRun=False,MaxResults=1000)
myEc2InstanceReservations = response['Reservations']

def ec2_instance_ssm_managed_check():
    for reservations in myEc2InstanceReservations:
        for instances in reservations['Instances']:
            instanceId = str(instances['InstanceId'])
            instanceArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':instance/' + instanceId
            instanceType = str(instances['InstanceType'])
            instanceImage = str(instances['ImageId'])
            instanceVpc = str(instances['VpcId'])
            instanceSubnet = str(instances['SubnetId'])
            instanceLaunchedAt = str(instances['LaunchTime'])
            try:
                response = ssm.describe_instance_information(
                    InstanceInformationFilterList=[
                        {
                            'key': 'InstanceIds',
                            'valueSet': [instanceId]
                        },
                    ]
                )
                if str(response['InstanceInformationList']) == '[]':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-managed-by-ssm-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 20 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.1] EC2 Instances should be managed by Systems Manager',
                                    'Description': 'EC2 Instance ' + instanceId + ' is not managed by Systems Manager. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-managed-by-ssm-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.1] EC2 Instances should be managed by Systems Manager',
                                    'Description': 'EC2 Instance ' + instanceId + ' is managed by Systems Manager.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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

def ssm_instace_agent_update_check(): 
    for reservations in myEc2InstanceReservations:
        for instances in reservations['Instances']:
            instanceId = str(instances['InstanceId'])
            instanceArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':instance/' + instanceId
            instanceType = str(instances['InstanceType'])
            instanceImage = str(instances['ImageId'])
            instanceVpc = str(instances['VpcId'])
            instanceSubnet = str(instances['SubnetId'])
            instanceLaunchedAt = str(instances['LaunchTime'])
            response = ssm.describe_instance_information()
            myManagedInstances = response['InstanceInformationList']
            for instances in myManagedInstances:
                latestVersionCheck = str(instances['IsLatestVersion'])
                if latestVersionCheck == 'False':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-ssm-agent-latest-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 40 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.2] EC2 Instances managed by Systems Manager should have the latest SSM Agent installed',
                                    'Description': 'EC2 Instance ' + instanceId + ' does not have the latest SSM Agent installed. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-ssm-agent-latest-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.2] EC2 Instances managed by Systems Manager should have the latest SSM Agent installed',
                                    'Description': 'EC2 Instance ' + instanceId + ' has the latest SSM Agent installed.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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

def ssm_instance_association_check():
    for reservations in myEc2InstanceReservations:
        for instances in reservations['Instances']:
            instanceId = str(instances['InstanceId'])
            instanceArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':instance/' + instanceId
            instanceType = str(instances['InstanceType'])
            instanceImage = str(instances['ImageId'])
            instanceVpc = str(instances['VpcId'])
            instanceSubnet = str(instances['SubnetId'])
            instanceLaunchedAt = str(instances['LaunchTime'])
            response = ssm.describe_instance_information()
            myManagedInstances = response['InstanceInformationList']
            for instances in myManagedInstances:
                associationStatusCheck = str(instances['AssociationStatus'])
                if associationStatusCheck != 'Success':
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-ssm-association-success-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 20 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.3] EC2 Instances managed by Systems Manager should have a successful Association status',
                                    'Description': 'EC2 Instance ' + instanceId + ' does not have a successful Association status. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-ssm-association-success-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 0 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.3] EC2 Instances managed by Systems Manager should have a successful Association status',
                                    'Description': 'EC2 Instance ' + instanceId + ' has a successful Association status.',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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

def ssm_instance_patch_state_state():
    for reservations in myEc2InstanceReservations:
        for instances in reservations['Instances']:
            instanceId = str(instances['InstanceId'])
            instanceArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + ':instance/' + instanceId
            instanceType = str(instances['InstanceType'])
            instanceImage = str(instances['ImageId'])
            instanceVpc = str(instances['VpcId'])
            instanceSubnet = str(instances['SubnetId'])
            instanceLaunchedAt = str(instances['LaunchTime'])
            response = ssm.describe_instance_information()
            try:
                response = ssm.describe_instance_patch_states(InstanceIds=[instanceId] )
                patchStatesCheck = str(response['InstancePatchStates'])
                if patchStatesCheck == '[]':
                    print('no patch info')
                    try:
                        # ISO Time
                        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        # create Sec Hub finding
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    'SchemaVersion': '2018-10-08',
                                    'Id': instanceArn + '/ec2-patch-manager-check',
                                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                    'GeneratorId': instanceArn,
                                    'AwsAccountId': awsAccountId,
                                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                    'FirstObservedAt': iso8601Time,
                                    'CreatedAt': iso8601Time,
                                    'UpdatedAt': iso8601Time,
                                    'Severity': { 'Normalized': 20 },
                                    'Confidence': 99,
                                    'Title': '[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager',
                                    'Description': 'EC2 Instance ' + instanceId + ' does not have any patch information recorded and is likely not managed by Patch Manager. Refer to the remediation instructions if this configuration is not intended',
                                    'Remediation': {
                                        'Recommendation': {
                                            'Text': 'For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide',
                                            'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html'
                                        }
                                    },
                                    'ProductFields': {
                                        'Product Name': 'ElectricEye'
                                    },
                                    'Resources': [
                                        {
                                            'Type': 'AwsEc2Instance',
                                            'Id': instanceArn,
                                            'Partition': 'aws',
                                            'Region': awsRegion,
                                            'Details': {
                                                'AwsEc2Instance': {
                                                    'Type': instanceType,
                                                    'ImageId': instanceImage,
                                                    'VpcId': instanceVpc,
                                                    'SubnetId': instanceSubnet,
                                                    'LaunchedAt': instanceLaunchedAt
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
                    patchStates = response['InstancePatchStates']
                    for patches in patchStates:
                        failedPatchCheck = str(patches['FailedCount'])
                        missingPatchCheck = str(patches['MissingCount'])
                        if failedPatchCheck != '0' or missingPatchCheck != '0':
                            try:
                                # ISO Time
                                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                                # create Sec Hub finding
                                response = securityhub.batch_import_findings(
                                    Findings=[
                                        {
                                            'SchemaVersion': '2018-10-08',
                                            'Id': instanceArn + '/ec2-patch-manager-check',
                                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                            'GeneratorId': instanceArn,
                                            'AwsAccountId': awsAccountId,
                                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                            'FirstObservedAt': iso8601Time,
                                            'CreatedAt': iso8601Time,
                                            'UpdatedAt': iso8601Time,
                                            'Severity': { 'Normalized': 40 },
                                            'Confidence': 99,
                                            'Title': '[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager',
                                            'Description': 'EC2 Instance ' + instanceId + ' is missing patches or has patches that failed to apply. Refer to the remediation instructions if this configuration is not intended',
                                            'Remediation': {
                                                'Recommendation': {
                                                    'Text': 'For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide',
                                                    'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html'
                                                }
                                            },
                                            'ProductFields': {
                                                'Product Name': 'ElectricEye'
                                            },
                                            'Resources': [
                                                {
                                                    'Type': 'AwsEc2Instance',
                                                    'Id': instanceArn,
                                                    'Partition': 'aws',
                                                    'Region': awsRegion,
                                                    'Details': {
                                                        'AwsEc2Instance': {
                                                            'Type': instanceType,
                                                            'ImageId': instanceImage,
                                                            'VpcId': instanceVpc,
                                                            'SubnetId': instanceSubnet,
                                                            'LaunchedAt': instanceLaunchedAt
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
                                # create Sec Hub finding
                                response = securityhub.batch_import_findings(
                                    Findings=[
                                        {
                                            'SchemaVersion': '2018-10-08',
                                            'Id': instanceArn + '/ec2-patch-manager-check',
                                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                                            'GeneratorId': instanceArn,
                                            'AwsAccountId': awsAccountId,
                                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                                            'FirstObservedAt': iso8601Time,
                                            'CreatedAt': iso8601Time,
                                            'UpdatedAt': iso8601Time,
                                            'Severity': { 'Normalized': 0 },
                                            'Confidence': 99,
                                            'Title': '[EC2-SSM.4] EC2 Instances managed by Systems Manager should have the latest patches installed by Patch Manager',
                                            'Description': 'EC2 Instance ' + instanceId + ' has the latest patches installed by Patch Manager.',
                                            'Remediation': {
                                                'Recommendation': {
                                                    'Text': 'For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide',
                                                    'Url': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html'
                                                }
                                            },
                                            'ProductFields': {
                                                'Product Name': 'ElectricEye'
                                            },
                                            'Resources': [
                                                {
                                                    'Type': 'AwsEc2Instance',
                                                    'Id': instanceArn,
                                                    'Partition': 'aws',
                                                    'Region': awsRegion,
                                                    'Details': {
                                                        'AwsEc2Instance': {
                                                            'Type': instanceType,
                                                            'ImageId': instanceImage,
                                                            'VpcId': instanceVpc,
                                                            'SubnetId': instanceSubnet,
                                                            'LaunchedAt': instanceLaunchedAt
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

def systems_manager_managed_instance_auditor():
    ec2_instance_ssm_managed_check()
    ssm_instance_association_check()
    ssm_instace_agent_update_check()
    ssm_instance_patch_state_state()

systems_manager_managed_instance_auditor()