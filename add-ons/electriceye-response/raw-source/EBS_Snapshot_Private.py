import boto3
import json
import os

def lambda_handler(event, context):
    # boto3 clients
    sts = boto3.client('sts')
    securityhub = boto3.client('securityhub')
    # create env vars
    awsRegion = os.environ['AWS_REGION']
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    masterAccountId = sts.get_caller_identity()['Account']
    # parse ASFF
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding ID
        findingId =str(findings['Id'])
        # parse Account from SecHub Finding
        findingOwner = str(findings['AwsAccountId'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            ebsSnapshot = resourceId.replace('arn:aws:ec2:' + awsRegion + '::snapshot/', '')
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                ec2 = boto3.client('ec2',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # remove public access from snapshot
                    response = ec2.modify_snapshot_attribute(
                        Attribute='createVolumePermission',
                        CreateVolumePermission={ 'Remove': [ { 'Group': 'all' }, ] },
                        OperationType='remove',
                        SnapshotId=ebsSnapshot,
                        DryRun=False
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'All public permissions were removed from the EBS snapshot and the finding was archived. Review the snapshot to ensure accounts that needed access were not removed, and that existing accounts are still authorized to have access.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    ec2 = boto3.client('ec2')
                    # apply bucket encryption
                    response = ec2.modify_snapshot_attribute(
                        Attribute='createVolumePermission',
                        CreateVolumePermission={ 'Remove': [ { 'Group': 'all' }, ] },
                        OperationType='remove',
                        SnapshotId=ebsSnapshot,
                        DryRun=False
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'All public permissions were removed from the EBS snapshot and the finding was archived. Review the snapshot to ensure accounts that needed access were not removed, and that existing accounts are still authorized to have access.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)