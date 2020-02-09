import boto3
import datetime
import os
# import boto3 clients
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')
# create aws account ID variable for filters
awsAccountId = sts.get_caller_identity()['Account']
awsRegion = os.environ['AWS_REGION']
try:
    # look for active high or critical findings from AWS products
    getFindings = securityhub.get_findings(
        Filters={
            # look for findings that belong to current account
            # will help deconflict checks run in a master account
            'AwsAccountId': [
                {
                    'Value': awsAccountId,
                    'Comparison': 'EQUALS'
                }
            ],
            # look for high or critical severity findings
            'SeverityLabel': [
                {
                    'Value': 'HIGH',
                    'Comparison': 'EQUALS'
                },
                {
                    'Value': 'CRITICAL',
                    'Comparison': 'EQUALS'
                }
            ],
            # look for AWS security hub integrations
            # company can be AWS or Amazon depending on service
            'CompanyName': [
                {
                    'Value': 'AWS',
                    'Comparison': 'EQUALS'
                },
                {
                    'Value': 'Amazon',
                    'Comparison': 'EQUALS'
                }
            ],
            # check for Active Records
            'RecordState': [
                {
                    'Value': 'ACTIVE',
                    'Comparison': 'EQUALS'
                }
            ]
        },
        SortCriteria=[
            {
                'Field': 'SeverityLabel',
                'SortOrder': 'asc'
            }
        ],
        MaxResults=100
    )          
except Exception as e:
    print(e)

if str(getFindings['Findings']) == '[]':
    generatorId = str(getFindings['ResponseMetadata']['RequestId'])
    try:
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        response = securityhub.batch_import_findings(
            Findings=[
                {
                    'SchemaVersion': '2018-10-08',
                    'Id': 'high-critical-findings-located/' + awsAccountId,
                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                    'GeneratorId': generatorId,
                    'AwsAccountId': awsAccountId,
                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                    'CreatedAt': iso8601Time,
                    'UpdatedAt': iso8601Time,
                    'Severity': { 'Normalized': 0 },
                    'Title': '[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services',
                    'Description': 'High or critical findings were not found in the Security Hub hub for AWS account ' + awsAccountId,
                    'Resources': [
                        {
                            'Type': 'AwsAccount',
                            'Id': awsAccountId,
                            'Partition': 'aws',
                            'Region': awsRegion
                        }
                    ],
                    'Compliance': {
                        'Status': 'PASSED'
                    },
                    'RecordState': 'ARCHIVED'
                }
            ]
        )
        print(response)
    except Exception as e:
        print(e)
else:
    generatorId = str(getFindings['ResponseMetadata']['RequestId'])
    try:
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        response = securityhub.batch_import_findings(
            Findings=[
                {
                    'SchemaVersion': '2018-10-08',
                    'Id': 'high-critical-findings-located/' + awsAccountId,
                    'ProductArn': 'arn:aws:securityhub:' + awsRegion + ':' + awsAccountId + ':product/' + awsAccountId + '/default',
                    'GeneratorId': generatorId,
                    'AwsAccountId': awsAccountId,
                    'Types': [ 'Software and Configuration Checks/AWS Security Best Practices' ],
                    'CreatedAt': iso8601Time,
                    'UpdatedAt': iso8601Time,
                    'Severity': {
                        'Normalized': 90
                    },
                    'Title': '[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services',
                    'Description': 'High or critical findings were found in the Security Hub hub for AWS account ' + awsAccountId,
                    'Resources': [
                        {
                            'Type': 'AwsAccount',
                            'Id': awsAccountId,
                            'Partition': 'aws',
                            'Region': awsRegion
                        }
                    ],
                    'Compliance': {
                        'Status': 'FAILED'
                    },
                    'RecordState': 'ACTIVE'
                }
            ]
        )
        print(response)
    except Exception as e:
        print(e)