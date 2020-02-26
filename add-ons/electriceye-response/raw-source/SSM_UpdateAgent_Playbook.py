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
                    # use ssm send command to update SSM agent
                    response = ssm.send_command(
                        InstanceIds=[ ec2InstanceId ],
                        DocumentName='AWS-UpdateSSMAgent',
                        DocumentVersion='$LATEST',
                        TimeoutSeconds=360,
                        Comment='SSM Agent update launched by ElectricEye response playbook',
                        CloudWatchOutputConfig={ 'CloudWatchOutputEnabled': True }
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Run Command was sent to invoke the AWS-UpdateSSMAgent document for the instance and the finding was archived. Re-run Electric Eye or view the Run Command execution list in the account that the Command was sent to to ensure it was successfully executed.','UpdatedBy': lambdaFunctionName},
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
                    # use ssm send command to update SSM agent
                    response = ssm.send_command(
                        InstanceIds=[ ec2InstanceId ],
                        DocumentName='AWS-UpdateSSMAgent',
                        DocumentVersion='$LATEST',
                        TimeoutSeconds=360,
                        Comment='SSM Agent update launched by ElectricEye response playbook',
                        CloudWatchOutputConfig={ 'CloudWatchOutputEnabled': True }
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Run Command was sent to invoke the AWS-UpdateSSMAgent document for the instance and the finding was archived. Re-run Electric Eye or view the Run Command execution list in the account that the Command was sent to to ensure it was successfully executed.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)