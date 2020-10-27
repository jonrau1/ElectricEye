import os
import boto3
import json
import requests

def lambda_handler(event, context):
    # create ssm client
    ssm = boto3.client('ssm')
    # Env var for SSM Param containing PagerDuty integration key
    integrationKeyParam = os.environ['PAGERDUTY_INTEGRATION_KEY_PARAMETER']
    # retrieve slack webhook from SSM
    try:
        response = ssm.get_parameter(Name=integrationKeyParam)
        pdIntegrationKey = str(response['Parameter']['Value'])
    except Exception as e:
        print(e)
    for findings in event['detail']['findings']:
        severityLabel = str(findings['Severity']['Label'])
        if severityLabel == 'CRITICAL':
            pdSev = str('critical')
        elif severityLabel == 'HIGH':
            pdSev = str('error')
        elif severityLabel == 'MEDIUM' or 'LOW':
            pdSev = str('warning')
        elif severityLabel == 'INFORMATIONAL':
            pdSev = str('info')
        else:
            pass
        electricEyeCheck = str(findings['Title'])
        findingDescription = str(findings['Description'])
        findingId = str(findings['Id'])
        awsAccountId = str(findings['AwsAccountId'])
        remediationReccText = str(findings['Remediation']['Recommendation']['Text'])
        remediationReccUrl = str(findings['Remediation']['Recommendation']['Url'])
        for resources in findings['Resources']:
            resourceType = str(resources['Type'])
            resourceId = str(resources['Id'])
            # create PagerDuty Payload
            pagerdutyEvent = {
                "payload": {
                    "summary": 'AWS account ' + awsAccountId + ' has failed ElectricEye check ' + electricEyeCheck,
                    "source": "ElectricEye",
                    "severity": pdSev,
                    "component": resourceId,
                    "class": "Security Hub Finding",
                    "custom_details": {
                        "finding_description": findingDescription,
                        "aws_account_id": awsAccountId,
                        "security_hub_severity": severityLabel,
                        "remediation_text": remediationReccText,
                        "remediation_url": remediationReccUrl,
                        "resource_type": resourceType
                    }
                },
                "dedup_key": findingId,
                "event_action": "trigger"
            }
            # pass content-type and the integration key headers
            pdHeaders = { 
                'Content-Type': 'application/json',
                'X-Routing-Key': pdIntegrationKey
            }   
            # this is a static value
            pdEventApiv2Url = 'https://events.pagerduty.com/v2/enqueue'
            # form a request from the URL, Headers, PagerDuty Event Action, De-Dupe Key and the Payload
            r = requests.post(pdEventApiv2Url, headers=pdHeaders, data=json.dumps(pagerdutyEvent))
            print(r)