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
import json

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
            repoName = resourceId.replace('arn:aws:ecr:' + awsRegion + ':' + findingOwner + ':repository/', '')
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                ecr = boto3.client('ecr',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # create a lifecycle policy that will expire untagged images if the total count moves above 2
                    ecrLifecyclePolicy = {
                    "rules": [
                        {
                        "rulePriority": 1,
                        "description": "Removes untagged images when there are more than 2",
                        "selection": {
                            "tagStatus": "untagged",
                            "countType": "imageCountMoreThan",
                            "countNumber": 2
                        },
                        "action": {
                            "type": "expire"
                        }
                        }
                    ]
                    }
                    try:
                        response = ecr.put_lifecycle_policy(repositoryName=repoName,lifecyclePolicyText=json.dumps(ecrLifecyclePolicy))
                        print(response)
                        try:
                            response = securityhub.update_findings(
                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                Note={'Text': 'The ECR repository had a Lifecycle Policy placed that will automatically delete any untagged images if the total count moves over two and the finding was archived.','UpdatedBy': lambdaFunctionName},
                                RecordState='ARCHIVED'
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    ecr = boto3.client('ecr')
                    # create a lifecycle policy that will expire untagged images if the total count moves above 2
                    ecrLifecyclePolicy = {
                    "rules": [
                        {
                        "rulePriority": 1,
                        "description": "Removes untagged images when there are more than 2",
                        "selection": {
                            "tagStatus": "untagged",
                            "countType": "imageCountMoreThan",
                            "countNumber": 2
                        },
                        "action": {
                            "type": "expire"
                        }
                        }
                    ]
                    }
                    try:
                        response = ecr.put_lifecycle_policy(repositoryName=repoName,lifecyclePolicyText=json.dumps(ecrLifecyclePolicy))
                        print(response)
                        try:
                            response = securityhub.update_findings(
                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                Note={'Text': 'The ECR repository had a Lifecycle Policy placed that will automatically delete any untagged images if the total count moves over two and the finding was archived.','UpdatedBy': lambdaFunctionName},
                                RecordState='ARCHIVED'
                            )
                            print(response)
                        except Exception as e:
                            print(e)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)