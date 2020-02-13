import boto3
import datetime
import os
# create boto3 clients
sts = boto3.client('sts')
ec2 = boto3.client('ec2')
securityhub = boto3.client('securityhub')
# create env vars
awsAccountId = sts.get_caller_identity()['Account']
#awsRegion = os.environ['AWS_REGION']
awsRegion = 'us-east-1'
# loop through vpcs
response = ec2.describe_vpcs(DryRun=False)
myVpcs = response['Vpcs']

def vpc_default_check():
    for vpcs in myVpcs:
        vpcId = str(vpcs['VpcId'])
        vpcArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + 'vpc/' + vpcId
        defaultVpcCheck = str(vpcs['IsDefault'])
        if defaultVpcCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': vpcArn + '/vpc-is-default-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': vpcArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[VPC.1] Consider deleting the Default VPC if unused',
                            'Description': 'VPC ' + vpcId + ' has been identified as the Default VPC, consider deleting this VPC if it is not necessary for daily operations. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Vpc',
                                    'Id': vpcArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'vpcId': vpcId }
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
                            'Id': vpcArn + '/vpc-is-default-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': vpcArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[VPC.1] Consider deleting the Default VPC if unused',
                            'Description': 'VPC ' + vpcId + ' is not the Default VPC',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Vpc',
                                    'Id': vpcArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'vpcId': vpcId }
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

def vpc_flow_logs_check():
    for vpcs in myVpcs:
        vpcId = str(vpcs['VpcId'])
        vpcArn = 'arn:aws:ec2:' + awsRegion + ':' + awsAccountId + 'vpc/' + vpcId
        response = ec2.describe_flow_logs(
            DryRun=False,
            Filters=[
                {
                    'Name': 'resource-id',
                    'Values': [ vpcId ]
                }
            ]
        )
        if str(response['FlowLogs']) == '[]':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': vpcArn + '/vpc-flow-log-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': vpcArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 20 },
                            'Confidence': 99,
                            'Title': '[VPC.2] Flow Logs should be enabled for all VPCs',
                            'Description': 'VPC ' + vpcId + ' does not have flow logging enabled. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Vpc',
                                    'Id': vpcArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'vpcId': vpcId }
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
                            'Id': vpcArn + '/vpc-flow-log-check',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                            'GeneratorId': vpcArn,
                            'AwsAccountId': awsAccountId,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[VPC.2] Flow Logs should be enabled for all VPCs',
                            'Description': 'VPC ' + vpcId + ' has flow logging enabled.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide',
                                    'Url': 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'AwsEc2Vpc',
                                    'Id': vpcArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'vpcId': vpcId }
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

def vpc_auditor():
    vpc_default_check()
    vpc_flow_logs_check()

vpc_auditor()