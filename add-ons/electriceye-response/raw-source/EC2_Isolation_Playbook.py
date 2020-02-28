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
                ec2 = boto3.client('ec2',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # create new SG for the compromised instance, remove egress and apply it
                    response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            vpcId = instance['VpcId']
                            try:
                                response = ec2.create_security_group(Description='Isolation SG',GroupName='isolate-'+ec2InstanceId,VpcId=vpcId,DryRun=False)
                                sgId = str(response['GroupId'])
                                try:
                                    response = ec2.revoke_security_group_egress(DryRun=False,GroupId=sgId,IpPermissions=[{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
                                    try:
                                        response = ec2.modify_instance_attribute(Groups=[sgId],InstanceId=ec2InstanceId)
                                        print(response)
                                        try:
                                            response = securityhub.update_findings(
                                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                Note={'Text': 'The instance was isolated by replacing the Security Group with one with no ingress or egress rules and the finding was archived. Consider performing forensics on the host if other behavior suggests an indicator of compromise. Delete the new Security Group after the instance has been dealt with','UpdatedBy': lambdaFunctionName},
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
                try:
                    ec2 = boto3.client('ec2')
                    # create new SG for the compromised instance, remove egress and apply it
                    response = ec2.describe_instances(InstanceIds=[ec2InstanceId],DryRun=False)
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            vpcId = instance['VpcId']
                            try:
                                response = ec2.create_security_group(Description='Isolation SG',GroupName='isolate-'+ec2InstanceId,VpcId=vpcId,DryRun=False)
                                sgId = str(response['GroupId'])
                                try:
                                    response = ec2.revoke_security_group_egress(DryRun=False,GroupId=sgId,IpPermissions=[{'IpProtocol': '-1','IpRanges': [{'CidrIp': '0.0.0.0/0'}]}])
                                    try:
                                        response = ec2.modify_instance_attribute(Groups=[sgId],InstanceId=ec2InstanceId)
                                        print(response)
                                        try:
                                            response = securityhub.update_findings(
                                                Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                                Note={'Text': 'The instance was isolated by replacing the Security Group with one with no ingress or egress rules and the finding was archived. Consider performing forensics on the host if other behavior suggests an indicator of compromise. Delete the new Security Group after the instance has been dealt with','UpdatedBy': lambdaFunctionName},
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