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
        if findingOwner != masterAccountId:
            memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
            # retrieve creds from member account
            xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
            xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
            xAcctSeshToken = memberAcct['Credentials']['SessionToken']
            # create service client using the assumed role credentials
            shield = boto3.client('shield',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
            try:
                # auto-renew shield adv subscription
                response = shield.update_subscription(AutoRenew='ENABLED')
                print(response)
                try:
                    response = securityhub.update_findings(
                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                        Note={'Text': 'Shield Advanced subscription has been set to auto-renew and the finding has been archived.','UpdatedBy': lambdaFunctionName},
                        RecordState='ARCHIVED'
                    )
                    print(response)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
        else:
            try:
                shield = boto3.client('shield')
                # auto-renew shield adv subscription
                response = shield.update_subscription(AutoRenew='ENABLED')
                print(response)
                try:
                    response = securityhub.update_findings(
                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                        Note={'Text': 'Shield Advanced subscription has been set to auto-renew and the finding has been archived.','UpdatedBy': lambdaFunctionName},
                        RecordState='ARCHIVED'
                    )
                    print(response)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)