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
                    'Severity': { 'Label': 'INFORMATIONAL' },
                    'Title': '[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services',
                    'Description': 'High or critical findings were not found in the Security Hub hub for AWS account ' + awsAccountId,
                    'ProductFields': { 'Product Name': 'ElectricEye' },
                    'Resources': [
                        {
                            'Type': 'AwsAccount',
                            'Id': 'AWS::::Account:' + awsAccountId,
                            'Partition': 'aws',
                            'Region': awsRegion
                        }
                    ],
                    'Compliance': { 
                        'Status': 'PASSED',
                        'RelatedRequirements': [
                            'NIST CSF DE.AE-2',
                            'NIST SP 800-53 AU-6',
                            'NIST SP 800-53 CA-7',
                            'NIST SP 800-53 IR-4',
                            'NIST SP 800-53 SI-4',
                            'AICPA TSC 7.2',
                            'ISO 27001:2013 A.12.4.1',
                            'ISO 27001:2013 A.16.1.1',
                            'ISO 27001:2013 A.16.1.4'
                        ]
                    },
                    'Workflow': {
                        'Status': 'RESOLVED'
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
                        'Label': 'CRITICAL'
                    },
                    'Title': '[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services',
                    'Description': 'High or critical findings were found in the Security Hub hub for AWS account ' + awsAccountId,
                    'ProductFields': { 'Product Name': 'ElectricEye' },
                    'Resources': [
                        {
                            'Type': 'AwsAccount',
                            'Id': 'AWS::::Account:' + awsAccountId,
                            'Partition': 'aws',
                            'Region': awsRegion
                        }
                    ],
                    'Compliance': { 
                        'Status': 'FAILED',
                        'RelatedRequirements': [
                            'NIST CSF DE.AE-2',
                            'NIST SP 800-53 AU-6',
                            'NIST SP 800-53 CA-7',
                            'NIST SP 800-53 IR-4',
                            'NIST SP 800-53 SI-4',
                            'AICPA TSC 7.2',
                            'ISO 27001:2013 A.12.4.1',
                            'ISO 27001:2013 A.16.1.1',
                            'ISO 27001:2013 A.16.1.4'
                        ]
                    },
                    'Workflow': {
                        'Status': 'NEW'
                    },
                    'RecordState': 'ACTIVE'
                }
            ]
        )
        print(response)
    except Exception as e:
        print(e)