#This file is part of ElectricEye.

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
import os
import boto3
import json
import urllib3
def lambda_handler(event, context):
    # create ssm client
    ssm = boto3.client('ssm')
    # create env var for SSM Parameter containing Slack Webhook URL
    webhookParam = os.environ['SLACK_WEBHOOK_PARAMETER']
    http = urllib3.PoolManager()
    # retrieve slack webhook from SSM
    try:
        response = ssm.get_parameter(Name=webhookParam)
        slackWebhook = str(response['Parameter']['Value'])
    except Exception as e:
        print(e)
    slackHeaders = { 'Content-Type': 'application/json' }
    for findings in event['detail']['findings']:
        severityLabel = str(findings['Severity']['Label'])
        electricEyeCheck = str(findings['Title'])
        awsAccountId = str(findings['AwsAccountId'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            slackMessage = 'A new ' + severityLabel + ' severity finding for ' + resourceId + ' in acccount ' + awsAccountId + ' has been created in Security Hub due to failing the check: ' + electricEyeCheck
            message = { 'text': slackMessage }
            http.request('POST', slackWebhook,  headers=slackHeaders, body=json.dumps(message).encode('utf-8'))