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
from jira import JIRA
import boto3
import os

# THIS REQUIRES THE LAMBDA LAYER FROM: https://github.com/jonrau1/ElectricEye/blob/master/add-ons/electriceye-response/lambda-layers/jira_lambda_layer.zip
def lambda_handler(event, context):
    # boto3 clients
    ssm = boto3.client('ssm')
    securityhub = boto3.client('securityhub')
    # create env vars
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    # JIRA specific variables
    jiraUrl = os.environ['JIRA_URL']
    jiraIssueCreatorUsername = os.environ['JIRA_ISSUE_CREATOR_USERNAME']
    jiraApiKeySSMParam = os.environ['JIRA_APIKEY_SSM_PARAM']
    jiraProjectKey = os.environ['JIRA_PROJECT_KEY']
    # decrypt & get API key from SSM
    response = ssm.get_parameter(Name=jiraApiKeySSMParam,WithDecryption=True)
    jiraApiKey = str(response['Parameter']['Value'])
    # JIRA project AuthN
    options = {'server': jiraUrl}
    jira = JIRA(options,auth=(jiraIssueCreatorUsername,jiraApiKey))
    # parse ASFF
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding details
        findingSeverity = str(findings['ProductFields']['aws/securityhub/SeverityLabel'])
        if findingSeverity == 'CRITICAL':
            jiraPriority = str('Highest')
        elif findingSeverity == 'HIGH':
            jiraPriority = str('High')
        elif findingSeverity == 'MEDIUM':
            jiraPriority = str('Medium')
        elif findingSeverity == 'LOW':
            jiraPriority = str('Low')
        elif findingSeverity == 'INFORMATIONAL':
            jiraPriority = str('Lowest')
        else:
            return 1
        findingId = str(findings['Id'])
        findingOwner = str(findings['AwsAccountId'])
        findingTitle = str(findings['Title'])
        findingDesc = str(findings['Description'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            new_issue = jira.create_issue(
                project=jiraProjectKey,
                summary=resourceId + ' has failed ' + findingTitle,
                description=resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle + ' Security Hub description includes the following information: ' + findingDesc, 
                issuetype={'name': 'Bug'},
                priority={'name': jiraPriority}
            )
            jiraIssueId = str(new_issue)
            try:
                response = securityhub.update_findings(
                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                    Note={'Text': 'The finding was either kept ACTIVE or moved back to an ACTIVE state. This finding has been created in the JIRA project ' + jiraProjectKey + ' as Issue ID ' + jiraIssueId,'UpdatedBy': lambdaFunctionName},
                    RecordState='ACTIVE'
                )
                print(response)
            except Exception as e:
                print(e)