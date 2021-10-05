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
import json
import os
import requests

def lambda_handler(event, context):
    # create Boto3 Clients
    ssm = boto3.client('ssm')
    securityhub = boto3.client('securityhub')
    # create env vars
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    # Azure DevOps specific env vars
    azureDevOpsPATParam = os.environ['AZURE_DEVOPS_PAT_SSM_PARAM_NAME']
    azureDevOpsOrg = os.environ['AZURE_DEVOPS_ORG']
    azureDevOpsProject = os.environ['AZURE_DEVOPS_PROJECT']
    azureDevOpsUrl = 'https://dev.azure.com/' + azureDevOpsOrg + '/' + azureDevOpsProject + '/_apis/wit/workitems/$issue?api-version=5.1'
    # retrieve the Azure Personal Access Token from SSM
    try:
        response = ssm.get_parameter(Name=azureDevOpsPATParam,WithDecryption=True)
        azureDevOpsPAT = str(response['Parameter']['Value'])
    except Exception as e:
        print(e)
        raise
    # parse ASFF
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding details
        findingSeverity = str(findings['ProductFields']['aws/securityhub/SeverityLabel'])
        if findingSeverity == 'CRITICAL':
            azurePriority = int(1)
        elif findingSeverity == 'HIGH':
            azurePriority = int(2)
        elif findingSeverity == 'MEDIUM':
            azurePriority = int(3)
        elif findingSeverity == 'LOW':
            azurePriority = int(4)
        elif findingSeverity == 'INFORMATIONAL':
            azurePriority = int(4)
        else:
            return 1
        findingId = str(findings['Id'])
        findingOwner = str(findings['AwsAccountId'])
        findingTitle = str(findings['Title'])
        findingDesc = str(findings['Description'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            rawPayload = [
                {
                    'op': 'add',
                    'path': '/fields/System.Title',
                    'from': None,
                    'value': resourceId + ' has failed ' + findingTitle
                },
                {
                    'op': 'add',
                    'path': '/fields/System.Description',
                    'from': None,
                    'value': resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle + ' Security Hub description includes the following information: ' + findingDesc
                },
                {
                    'op': 'add',
                    'path': '/fields/Microsoft.VSTS.Common.Priority',
                    'from': None,
                    'value': azurePriority
                },
                {
                    'op': 'add',
                    'path': '/fields/System.Tags',
                    'from': None,
                    'value': 'securityhub; aws'
                }
            ]
            payload = json.dumps(rawPayload)
            headers = {'Content-Type': 'application/json-patch+json'}
            # create the Azure DevOps Work Item
            response = requests.post(azureDevOpsUrl,auth=('',azureDevOpsPAT),headers=headers,data=payload)
            # Parse Item number and create the URL for SecHub UF API Call
            json_data = json.loads(response.text)
            azureWitId = str(json_data['id'])
            azureWitUrl = 'https://dev.azure.com/' + azureDevOpsOrg + '/' + azureDevOpsProject + '/_workitems/edit/' + azureWitId + '/'
            # call UpdateFindings API to add a note with the Azure DevOps WIT URL
            try:
                response = securityhub.update_findings(
                    Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                    Note={'Text': 'The finding was either kept ACTIVE or moved back to an ACTIVE state. This finding has been created in the Azure DevOps project ' + azureDevOpsProject + ' as Issue ID ' + azureWitId + ' which can be viewed at ' + azureWitUrl,'UpdatedBy': lambdaFunctionName},
                    RecordState='ACTIVE'
                )
                print(response)
            except Exception as e:
                print(e)