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
    lambdaFunctionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    masterAccountId = sts.get_caller_identity()['Account']
    # ServiceNow specific variables
    snowIncidentUser = os.environ['SERVICENOW_INCIDENT_CREATOR']
    snowIncidentPassword = os.environ['SERVICENOW_INCIDENT_CREATOR_PW_PARAM']
    snowURL = os.environ['SERVICENOW_URL']
    # parse ASFF
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding details
        findingSeverity = str(findings['ProductFields']['aws/securityhub/SeverityLabel'])
        if findingSeverity == 'CRITICAL':
            snowImpact = str('High')
            snowUrgency = str('High')
        elif findingSeverity == 'HIGH':
            snowImpact = str('High')
            snowUrgency = str('High')
        elif findingSeverity == 'MEDIUM':
            snowImpact = str('Medium')
            snowUrgency = str('Medium')
        elif findingSeverity == 'LOW':
            snowImpact = str('Low')
            snowUrgency = str('Low')
        elif findingSeverity == 'INFORMATIONAL':
            snowImpact = str('Low')
            snowUrgency = str('Low')
        else:
            return 1
        findingId = str(findings['Id'])
        findingOwner = str(findings['AwsAccountId'])
        findingTitle = str(findings['Title'])
        findingDesc = str(findings['Description'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            if findingOwner != masterAccountId:
                memberAcct = sts.assume_role(RoleArn='arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response',RoleSessionName='x_acct_sechub')
                # retrieve creds from member account
                xAcctAccessKey = memberAcct['Credentials']['AccessKeyId']
                xAcctSecretKey = memberAcct['Credentials']['SecretAccessKey']
                xAcctSeshToken = memberAcct['Credentials']['SessionToken']
                # create service client using the assumed role credentials
                ssm = boto3.client('ssm',aws_access_key_id=xAcctAccessKey,aws_secret_access_key=xAcctSecretKey,aws_session_token=xAcctSeshToken)
                try:
                    # use ssm automation to create a ServiceNow Incident
                    response = ssm.start_automation_execution(
                        DocumentName='AWS-CreateServiceNowIncident',
                        DocumentVersion='1',
                        Parameters={
                            'ServiceNowInstanceUsername': [snowIncidentUser],
                            'ServiceNowInstancePassword': [snowIncidentPassword],
                            'ServiceNowInstanceURL': [snowURL],
                            'ShortDescription': [resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle],
                            'Description': [resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle + ' Security Hub description includes the following information: ' + findingDesc],
                            'Impact': [snowImpact],
                            'Urgency': [snowUrgency],
                            'AutomationAssumeRole': ['arn:aws:iam::' + findingOwner + ':role/XA-ElectricEye-Response']
                        },
                        Mode='Auto'
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Systems Manager Automation was started to invoke the AWS-CreateServiceNowIncident document for the finding and it was archived. View the Automation execution list to ensure it was successfully executed and to receive the Incident number for this finding.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)
            else:
                try:
                    ssm = boto3.client('ssm')
                    # use ssm automation to create a ServiceNow Incident
                    response = ssm.start_automation_execution(
                        DocumentName='AWS-CreateServiceNowIncident',
                        DocumentVersion='1',
                        Parameters={
                            'ServiceNowInstanceUsername': [snowIncidentUser],
                            'ServiceNowInstancePassword': [snowIncidentPassword],
                            'ServiceNowInstanceURL': [snowURL],
                            'ShortDescription': [resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle],
                            'Description': [resourceId + ' in account ' + findingOwner + ' has failed check ' + findingTitle + ' Security Hub description includes the following information: ' + findingDesc],
                            'Impact': [snowImpact],
                            'Urgency': [snowUrgency]
                        },
                        Mode='Auto'
                    )
                    print(response)
                    try:
                        response = securityhub.update_findings(
                            Filters={'Id': [{'Value': findingId,'Comparison': 'EQUALS'}]},
                            Note={'Text': 'Systems Manager Automation was started to invoke the AWS-CreateServiceNowIncident document for the finding and it was archived. View the Automation execution list to ensure it was successfully executed and to receive the Incident number for this finding.','UpdatedBy': lambdaFunctionName},
                            RecordState='ARCHIVED'
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                except Exception as e:
                    print(e)