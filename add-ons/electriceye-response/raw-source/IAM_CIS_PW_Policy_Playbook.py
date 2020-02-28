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
        if findingOwner != masterAcctId:
            memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
            # retrieve creds from member account
            xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
            xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
            xAcctSeshToken = memberAcct['Credentials']['SessionToken']
            # create service client using the assumed role credentials
            iam = boto3.client('iam',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
            try:
                response = iam.update_account_password_policy(
                    MinimumPasswordLength=15,
                    RequireSymbols=True,
                    RequireNumbers=True,
                    RequireUppercaseCharacters=True,
                    RequireLowercaseCharacters=True,
                    AllowUsersToChangePassword=True,
                    MaxPasswordAge=90,
                    PasswordReusePrevention=24,
                    HardExpiry=True
                    )
                print(response)
                try:
                    response = securityhub.update_findings(
                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                        Note={'Text': 'Your AWS Account IAM Password policy has been updated to meet all requirements defined by CIS. Refer to the CIS Controls 1.5 through 1.11 to ensure the change has taken place and investigate further to determine if this was a result of malicious activity.','UpdatedBy': lambdaFunctionName},
                        RecordState='ARCHIVED'
                    )
                    print(response)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        else:
            try:
                iam = boto3.client('iam')
                response = iam.update_account_password_policy(
                    MinimumPasswordLength=14,
                    RequireSymbols=True,
                    RequireNumbers=True,
                    RequireUppercaseCharacters=True,
                    RequireLowercaseCharacters=True,
                    AllowUsersToChangePassword=True,
                    MaxPasswordAge=90,
                    PasswordReusePrevention=24,
                    HardExpiry=True
                    )
                print(response)
                try:
                    response = securityhub.update_findings(
                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                        Note={'Text': 'Your AWS Account IAM Password policy has been updated to meet all requirements defined by CIS. Refer to the CIS Controls 1.5 through 1.11 to ensure the change has taken place and investigate further to determine if this was a result of malicious activity.','UpdatedBy': lambdaFunctionName},
                        RecordState='ARCHIVED'
                    )
                    print(response)
                except Exception as e:
                    print(e)   
            except Exception as e:
                print(e)