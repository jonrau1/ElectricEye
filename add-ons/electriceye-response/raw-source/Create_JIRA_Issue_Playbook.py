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