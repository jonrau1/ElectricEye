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
            esDomainName = resourceId.replace('arn:aws:es:' + awsRegion + ':' + findingOwner + ':domain/', '')
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                es = boto3.client('es',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                logs = boto3.client('logs',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # create log group
                    response = logs.create_log_group(logGroupName='ES/ErrorLogs/'+esDomainName)
                    time.sleep(4)
                    try:
                        # get the CWL ARN
                        response = logs.describe_log_groups(logGroupNamePrefix='ES/ErrorLogs/'+esDomainName)
                        for group in response['logGroups']:
                            logGroupArn = str(group['arn'])
                            # create a RBP for ES to publish to CWL
                            try:
                                esCwlPolicy = {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                        "Effect": "Allow",
                                        "Principal": {
                                            "Service": "es.amazonaws.com"
                                        },
                                        "Action": [
                                            "logs:PutLogEvents",
                                            "logs:CreateLogStream"
                                        ],
                                        "Resource": logGroupArn
                                        }
                                    ]
                                }
                                response = logs.put_resource_policy(
                                    policyName='ES-log-publishing-'+esDomainName,
                                    policyDocument=json.dumps(esCwlPolicy)
                                )
                                print(response)
                                time.sleep(3)
                                try:
                                    # configure ES logging for App/Error logs
                                    response = es.update_elasticsearch_domain_config(
                                        DomainName=esDomainName,
                                        LogPublishingOptions={ 'ES_APPLICATION_LOGS': { 'CloudWatchLogsLogGroupArn':logGroupArn,'Enabled':True } } )
                                    print(response)
                                    try:
                                        response = securityhub.update_findings(
                                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                            Note={'Text': 'The Elasticsearch Service domain has been configured to log Application logs, including error logs, to CloudWatch Logs and the finding was archived. CloudWatch Logs only supports 10 resource-based policies per region, review these to ensure you are not at the limit.','UpdatedBy': lambdaFunctionName},
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
                    es = boto3.client('es')
                    logs = boto3.client('logs')
                    # create log group
                    response = logs.create_log_group(logGroupName='ES/ErrorLogs/'+esDomainName)
                    time.sleep(4)
                    try:
                        # get the CWL ARN
                        response = logs.describe_log_groups(logGroupNamePrefix='ES/ErrorLogs/'+esDomainName)
                        for group in response['logGroups']:
                            logGroupArn = str(group['arn'])
                            # create a RBP for ES to publish to CWL
                            try:
                                esCwlPolicy = {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                        "Effect": "Allow",
                                        "Principal": {
                                            "Service": "es.amazonaws.com"
                                        },
                                        "Action": [
                                            "logs:PutLogEvents",
                                            "logs:CreateLogStream"
                                        ],
                                        "Resource": logGroupArn
                                        }
                                    ]
                                }
                                response = logs.put_resource_policy(
                                    policyName='ES-log-publishing-'+esDomainName,
                                    policyDocument=json.dumps(esCwlPolicy)
                                )
                                print(response)
                                time.sleep(3)
                                try:
                                    # configure ES logging for App/Error logs
                                    response = es.update_elasticsearch_domain_config(
                                        DomainName=esDomainName,
                                        LogPublishingOptions={ 'ES_APPLICATION_LOGS': { 'CloudWatchLogsLogGroupArn':logGroupArn,'Enabled':True } } )
                                    print(response)
                                    try:
                                        response = securityhub.update_findings(
                                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                                            Note={'Text': 'The Elasticsearch Service domain has been configured to log Application logs, including error logs, to CloudWatch Logs and the finding was archived. CloudWatch Logs only supports 10 resource-based policies per region, review these to ensure you are not at the limit.','UpdatedBy': lambdaFunctionName},
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