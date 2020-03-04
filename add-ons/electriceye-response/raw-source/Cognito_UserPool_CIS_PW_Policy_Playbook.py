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
    # parse Security Hub CWE
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding ID
        findingId =str(findings['Id'])
        # parse Account from SecHub Finding
        findingOwner = str(findings['AwsAccountId'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            # create resource ID
            cognitoUserPoolId = resourceId.replace('arn:aws:cognito-idp:' + awsRegion + ':' + findingOwner + ':userpool/', '')
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                cognitoidp = boto3.client('cognito-idp',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # modify Cognito User Pool password policy to be compliant with CIS password requirements
                    response = cognitoidp.update_user_pool(
                        UserPoolId=cognitoUserPoolId,
                        Policies={
                            'PasswordPolicy': {
                                'MinimumLength': 14,
                                'RequireUppercase': True,
                                'RequireLowercase': True,
                                'RequireNumbers': True,
                                'RequireSymbols': True
                            }
                        }
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'The Cognito User Pool password policy was updated to be compliant with CIS requirements and the finding was archived. Review the Cognito User Pool for any other unauthorized configurations.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    cognitoidp = boto3.client('cognito-idp')
                    # modify Cognito User Pool password policy to be compliant with CIS password requirements
                    response = cognitoidp.update_user_pool(
                        UserPoolId=cognitoUserPoolId,
                        Policies={
                            'PasswordPolicy': {
                                'MinimumLength': 14,
                                'RequireUppercase': True,
                                'RequireLowercase': True,
                                'RequireNumbers': True,
                                'RequireSymbols': True
                            }
                        }
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'The Cognito User Pool password policy was updated to be compliant with CIS requirements and the finding was archived. Review the Cognito User Pool for any other unauthorized configurations.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)