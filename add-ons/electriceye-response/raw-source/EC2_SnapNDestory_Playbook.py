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
                                                            # remove deletion protection if it exists
                                                            response = ec2.modify_instance_attribute(InstanceId=ec2InstanceId,DisableApiTermination={'Value':False})
                                                            print(response)
                                                            try:
                                                                # terminate instance
                                                                response = ec2.terminate_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                                                                print(response)
                                                                try:
                                                                    response = securityhub.update_findings(
                                                                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                                        Note={'Text': 'The EC2 instance was stopped, a snapshot was created, the instance was terminated and the finding was archived. Perform forensics on the snapshot per DFIR policies.','UpdatedBy': lambdaFunctionName},
                                                                        RecordState='ARCHIVED'
                                                                    )
                                                                    print(response)
                                                                except Exception as e:
                                                                    print(e)
                                                            except Exception as e:
                                                                print(e)
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
                                                            # remove deletion protection if it exists
                                                            response = ec2.modify_instance_attribute(InstanceId=ec2InstanceId,DisableApiTermination={'Value':False})
                                                            print(response)
                                                            try:
                                                                # terminate instance
                                                                response = ec2.terminate_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                                                                print(response)
                                                                try:
                                                                    response = securityhub.update_findings(
                                                                        Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                                        Note={'Text': 'The EC2 instance was stopped, a snapshot was created, the instance was terminated and the finding was archived. Perform forensics on the snapshot per DFIR policies.','UpdatedBy': lambdaFunctionName},
                                                                        RecordState='ARCHIVED'
                                                                    )
                                                                    print(response)
                                                                except Exception as e:
                                                                    print(e)
                                                            except Exception as e:
                                                                print(e)
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