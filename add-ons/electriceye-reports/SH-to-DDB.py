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
import json
import os
def lambda_handler(event, context):
    awsRegion = os.environ['AWS_REGION']
    electricDdbTable = os.environ['ELECTRIC_EYE_DDB_TABLE']
    securityHubEvent = (event['detail']['findings'])
    for findings in securityHubEvent:
        # parse finding ID
        findingTypes = findings['Types']
        findingCreationDate = str(findings['CreatedAt'])
        findingId = str(findings['Id'])
        findingOwner = str(findings['AwsAccountId'])
        findingTitle = str(findings['Title'])
        findingSeverity = str(findings['ProductFields']['aws/securityhub/SeverityLabel'])
        for resources in findings['Resources']:
            resourceId = str(resources['Id'])
            resourceType = str(resources['Type'])
            resourceRegion = str(resources['Region'])
            try:
                dynamodb = boto3.resource('dynamodb', region_name=awsRegion)
                table = dynamodb.Table(electricDdbTable)
                response = table.put_item(
                    Item={
                        'FINDING_ID': findingId,
                        'FINDING_CREATION': findingCreationDate,
                        'FINDING_TYPES': [findingTypes],
                        'AWS_ACCOUNT': findingOwner,
                        'FINDING_TITLE': findingTitle,
                        'FINDING_SEV': findingSeverity,
                        'RESOURCE_ID': resourceId,
                        'RESOURCE_TYPE': resourceType,
                        'RESOURCE_REGION': resourceRegion
                    }
                )
                print(response)
            except Exception as e:
                print(e)