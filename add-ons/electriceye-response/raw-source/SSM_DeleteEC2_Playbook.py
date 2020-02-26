import boto3
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
            ec2InstanceId = resourceId.replace('arn:aws:ec2:' + awsRegion + ':' + findingOwner + ':instance/', '')
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                ssm = boto3.client('ssm',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # use ssm automation to terminate EC2 instance
                    response = ssm.start_automation_execution(
                        DocumentName='AWS-TerminateEC2Instance',
                        DocumentVersion='1',
                        Parameters={
                            'InstanceId': [ ec2InstanceId ],
                            'AutomationAssumeRole': ['arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response']
                        },
                        Mode='Auto'
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Systems Manager Automation was started to invoke the AWS-TerminateEC2Instance document for the instance and the finding was archived. Re-run Electric Eye or view the Automation execution list in the account that the Command was sent to to ensure it was successfully executed.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    ssm = boto3.client('ssm')
                    # use ssm automation to terminate EC2 instance
                    response = ssm.start_automation_execution(
                        DocumentName='AWS-TerminateEC2Instance',
                        DocumentVersion='1',
                        Parameters={
                            'InstanceId': [ ec2InstanceId ],
                            'AutomationAssumeRole': ['arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response']
                        },
                        Mode='Auto'
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Systems Manager Automation was started to invoke the AWS-TerminateEC2Instance document for the instance and the finding was archived. Re-run Electric Eye or view the Automation execution list in the account that the Command was sent to to ensure it was successfully executed.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)