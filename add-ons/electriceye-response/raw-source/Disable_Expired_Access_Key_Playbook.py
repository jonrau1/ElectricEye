#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.
import boto3
import os
import datetime

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
            nonRotatedKeyUser = resourceId.replace('arn:aws:iam::' + findingOwner + ':user/', '') 
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                iam_resource = boto3.resource('iam',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                iam = boto3.client('iam',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
                    paginator = iam.get_paginator('list_access_keys')
                    for response in paginator.paginate(UserName=nonRotatedKeyUser):
                        for keyMetadata in response['AccessKeyMetadata']:
                            accessKeyId = str(keyMetadata['AccessKeyId'])
                            keyAgeFinder = todaysDatetime - keyMetadata['CreateDate']
                            if keyAgeFinder <= datetime.timedelta(days=90):
                                print(accessKeyId + ' is not over 90 days old')
                            else:
                                print(accessKeyId + ' is over 90 days old!')
                                access_key = iam_resource.AccessKey(nonRotatedKeyUser, accessKeyId)
                                access_key.deactivate()
                                get_KeyStatus = iam.list_access_keys(UserName=nonRotatedKeyUser,MaxItems=20)
                                for keys in get_KeyStatus['AccessKeyMetadata']:
                                    access_KeyId = str(keys['AccessKeyId'])
                                    access_KeyStatus = str(keys['Status'])
                                    # find the key Id that matches the exposed key
                                    if access_KeyId == accessKeyId:
                                        if access_KeyStatus == 'Inactive':
                                            print('Access key over 90 days old deactivated!')
                                            try:
                                                response = securityhub.update_findings(
                                                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                    Note={'Text': 'All IAM Access Keys over 90 days old for the identified IAM user have been deactivated and the finding was archived. Review any downstream services that may have been dependent on these credentials to ensure they are still operating correctly.','UpdatedBy': lambdaFunctionName},
                                                    RecordState='ACTIVE'
                                                )
                                                print(response)
                                            except Exception as e:
                                                print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    iam_resource = boto3.resource('iam')
                    iam = boto3.client('iam')
                    todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
                    paginator = iam.get_paginator('list_access_keys')
                    for response in paginator.paginate(UserName=nonRotatedKeyUser):
                        for keyMetadata in response['AccessKeyMetadata']:
                            accessKeyId = str(keyMetadata['AccessKeyId'])
                            keyAgeFinder = todaysDatetime - keyMetadata['CreateDate']
                            if keyAgeFinder <= datetime.timedelta(days=90):
                                print(accessKeyId + ' is not over 90 days old')
                            else:
                                print(accessKeyId + ' is over 90 days old!')
                                access_key = iam_resource.AccessKey(nonRotatedKeyUser, accessKeyId)
                                access_key.deactivate()
                                get_KeyStatus = iam.list_access_keys(UserName=nonRotatedKeyUser,MaxItems=20)
                                for keys in get_KeyStatus['AccessKeyMetadata']:
                                    access_KeyId = str(keys['AccessKeyId'])
                                    access_KeyStatus = str(keys['Status'])
                                    # find the key Id that matches the exposed key
                                    if access_KeyId == accessKeyId:
                                        if access_KeyStatus == 'Inactive':
                                            print('Access key over 90 days old deactivated!')
                                            try:
                                                response = securityhub.update_findings(
                                                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                    Note={'Text': 'All IAM Access Keys over 90 days old for the identified IAM user have been deactivated and the finding was archived. Review any downstream services that may have been dependent on these credentials to ensure they are still operating correctly.','UpdatedBy': lambdaFunctionName},
                                                    RecordState='ACTIVE'
                                                )
                                                print(response)
                                            except Exception as e:
                                                print(e)
                except Exception as e:
                    print(e)