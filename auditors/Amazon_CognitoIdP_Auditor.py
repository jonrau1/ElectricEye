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
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
cognitoidp = boto3.client('cognito-idp')
sts = boto3.client('sts')
# create account id & region variables
awsAccount = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']

def cognitoidp_cis_password_check():
    response = cognitoidp.list_user_pools(MaxResults=60)
    myCognitoUserPools = response['UserPools']
    for userpools in myCognitoUserPools:
        userPoolId = str(userpools['Id'])
        response = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(response['UserPool']['Arn'])
        userPoolId = str(response['UserPool']['Id'])
        cognitoPwPolicy = response['UserPool']['Policies']['PasswordPolicy']
        minLengthCheck = int(cognitoPwPolicy['MinimumLength'])
        uppercaseCheck = str(cognitoPwPolicy['RequireUppercase'])
        lowercaseCheck = str(cognitoPwPolicy['RequireLowercase'])
        numberCheck = str(cognitoPwPolicy['RequireNumbers'])
        symbolCheck = str(cognitoPwPolicy['RequireSymbols'])
        if minLengthCheck >= 14 and uppercaseCheck == 'True' and lowercaseCheck == 'True' and numberCheck == 'True' and symbolCheck == 'True':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userPoolArn + '/cognito-user-pool-password-policy',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.1] Cognito user pools should have a password policy that meets or exceed AWS CIS Foundations Benchmark standards',
                            'Description': 'Cognito user pool ' + userPoolArn + ' does not meet the password guidelines. Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To ensure you Cognito user pools have a password policy that meets or exceed AWS CIS Foundations Benchmark standards refer to the Adding User Pool Password Requirements section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
                            'Id': userPoolArn + '/cognito-user-pool-password-policy',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.1] Cognito user pools should have a password policy that meets or exceed AWS CIS Foundations Benchmark standards',
                            'Description': 'Cognito user pool ' + userPoolArn + ' meets the password guidelines.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To ensure you Cognito user pools have a password policy that meets or exceed AWS CIS Foundations Benchmark standards refer to the Adding User Pool Password Requirements section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
            
def cognitoidp_temp_password_check():
    response = cognitoidp.list_user_pools(MaxResults=60)
    myCognitoUserPools = response['UserPools']
    for userpools in myCognitoUserPools:
        userPoolId = str(userpools['Id'])
        response = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(response['UserPool']['Arn'])
        userPoolId = str(response['UserPool']['Id'])
        cognitoPwPolicy = response['UserPool']['Policies']['PasswordPolicy']
        tempPwValidityCheck = int(cognitoPwPolicy['TemporaryPasswordValidityDays'])
        if tempPwValidityCheck > 1:
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userPoolArn + '/cognito-user-pool-temp-password-life',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 40 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.2] Cognito user pools should not allow temporary passwords to stay valid beyond 24 hours',
                            'Description': 'Cognito user pool ' + userPoolArn + ' allows temporary passwords to stay valid beyond 24 hours. Refer to the remediation instructions if this configuration is not intended',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To modify your Cognito user pool temporary password policy refer to the Authentication Flow for Users Created by Administrators or Developers section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
                            'Id': userPoolArn + '/cognito-user-pool-temp-password-life',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.2] Cognito user pools should not allow temporary passwords to stay valid beyond 24 hours',
                            'Description': 'Cognito user pool ' + userPoolArn + ' does not allow temporary passwords to stay valid beyond 24 hours.',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To modify your Cognito user pool temporary password policy refer to the Authentication Flow for Users Created by Administrators or Developers section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
            
def cognitoidp_mfa_check():
    response = cognitoidp.list_user_pools(MaxResults=60)
    myCognitoUserPools = response['UserPools']
    for userpools in myCognitoUserPools:
        userPoolId = str(userpools['Id'])
        response = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(response['UserPool']['Arn'])
        userPoolId = str(response['UserPool']['Id'])
        mfaCheck = str(response['UserPool']['MfaConfiguration'])
        if mfaCheck != 'ON':
            try:
                # ISO Time
                iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                # create Sec Hub finding
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            'SchemaVersion': '2018-10-08',
                            'Id': userPoolArn + '/cognito-user-pool-mfa',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 80 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.3] Cognito user pools should enforce multi factor authentication (MFA)',
                            'Description': 'Cognito user pool ' + userPoolArn + ' does not enforce multi factor authentication (MFA). Refer to the remediation instructions to remediate this behavior',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To ensure you Cognito user pools enforce MFA refer to the Adding Multi-Factor Authentication (MFA) to a User Pool section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
                            'Id': userPoolArn + '/cognito-user-pool-mfa',
                            'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccount + ':product/' + awsAccount + '/default',
                            'GeneratorId': userPoolId,
                            'AwsAccountId': awsAccount,
                            'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                            'FirstObservedAt': iso8601Time,
                            'CreatedAt': iso8601Time,
                            'UpdatedAt': iso8601Time,
                            'Severity': { 'Normalized': 0 },
                            'Confidence': 99,
                            'Title': '[Cognito-IdP.3] Cognito user pools should enforce multi factor authentication (MFA)',
                            'Description': 'Cognito user pool ' + userPoolArn + ' enforces multi factor authentication (MFA).',
                            'Remediation': {
                                'Recommendation': {
                                    'Text': 'To ensure you Cognito user pools enforce MFA refer to the Adding Multi-Factor Authentication (MFA) to a User Pool section of the Amazon Cognito Developer Guide',
                                    'Url': 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html'
                                }
                            },
                            'ProductFields': {
                                'Product Name': 'ElectricEye'
                            },
                            'Resources': [
                                {
                                    'Type': 'Other',
                                    'Id': userPoolArn,
                                    'Partition': 'aws',
                                    'Region': awsRegion,
                                    'Details': {
                                        'Other': { 'UserPoolId': userPoolId }
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
            
def cognitoidp_audit():
    cognitoidp_cis_password_check()
    cognitoidp_temp_password_check()
    cognitoidp_mfa_check()
    
cognitoidp_audit()