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
import time
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
                ec2 = boto3.client('ec2',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # force stop an instance
                    response = ec2.stop_instances(InstanceIds=[ec2InstanceId],DryRun=False,Force=True)
                    # wait a little bit for the instance to stop
                    print(response) 
                    time.sleep(33)
                    try:
                        # loop through instance info again
                        response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                        for reservation in response['Reservations']:
                            for instance in reservation['Instances']:
                                # wait until the instance is stopped
                                ec2State = str(instance['State']['Name'])
                                if ec2State == 'stopped':
                                    try:
                                        # loop through instance info
                                        response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                                        for reservation in response['Reservations']:
                                            for instance in reservation['Instances']:
                                                for volumes in instance['BlockDeviceMappings']:
                                                    volumeId = str(volumes['Ebs']['VolumeId'])
                                                    try:
                                                        # create snapshot(s)
                                                        response = ec2.create_snapshot(
                                                            Description='Created by a Security Hub response and remedation Playbook used for forensic snapshotting and instance destruction',
                                                            VolumeId=volumeId,
                                                            TagSpecifications=[ { 'ResourceType': 'snapshot','Tags': [ {'Key': 'Name','Value': ec2InstanceId+' forensic-snapshot'} ] } ],
                                                            DryRun=False
                                                        )
                                                        print(response)
                                                        try:
                                                            response = securityhub.update_findings(
                                                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                                Note={'Text': 'The EC2 instance was stopped, a snapshot was created and the finding was archived. Perform forensics on the snapshot per DFIR policies. Consider Terminating the instance when forensics are complete.','UpdatedBy': lambdaFunctionName},
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
                                    exit
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    # force stop an instance
                    response = ec2.stop_instances(InstanceIds=[ec2InstanceId],DryRun=False,Force=True)
                    # wait a little bit for the instance to stop
                    print(response) 
                    time.sleep(33)
                    try:
                        # loop through instance info again
                        response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                        for reservation in response['Reservations']:
                            for instance in reservation['Instances']:
                                # wait until the instance is stopped
                                ec2State = str(instance['State']['Name'])
                                if ec2State == 'stopped':
                                    try:
                                        # loop through instance info
                                        response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                                        for reservation in response['Reservations']:
                                            for instance in reservation['Instances']:
                                                for volumes in instance['BlockDeviceMappings']:
                                                    volumeId = str(volumes['Ebs']['VolumeId'])
                                                    try:
                                                        # create snapshot(s)
                                                        response = ec2.create_snapshot(
                                                            Description='Created by a Security Hub response and remedation Playbook used for forensic snapshotting and instance destruction',
                                                            VolumeId=volumeId,
                                                            TagSpecifications=[ { 'ResourceType': 'snapshot','Tags': [ {'Key': 'Name','Value': ec2InstanceId+' forensic-snapshot'} ] } ],
                                                            DryRun=False
                                                        )
                                                        print(response)
                                                        try:
                                                            response = securityhub.update_findings(
                                                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                                Note={'Text': 'The EC2 instance was stopped, a snapshot was created and the finding was archived. Perform forensics on the snapshot per DFIR policies. Consider Terminating the instance when forensics are complete.','UpdatedBy': lambdaFunctionName},
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
                                    exit
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)