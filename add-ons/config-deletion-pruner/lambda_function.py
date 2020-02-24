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
    # import Lambda runtime env var for function name
    functionName = os.environ['AWS_LAMBDA_FUNCTION_NAME']
    # create boto3 clients
    securityhub = boto3.client('securityhub')
    # parse deleted resource ARN and resource ID from Config Event
    # Resource.[i].Id in the ASFF *should* be the ARN but just in case try both
    try:
        deletedResourceArn = str(event['detail']['configurationItem']['ARN'])
    except Exception as e:
        print(e)
    try:
        deletedResourceId = str(event['detail']['configurationItem']['resourceId'])
    except Exception as e:
        print(e)
    # archive all findings related to resource ARN
    try:
        response = securityhub.update_findings(
            Filters={'ResourceId': [{'Value': deletedResourceArn,'Comparison': 'EQUALS'}]},
            Note={
                'Text': 'The resource related to this finding was identified as being deleted from AWS Config and has been archived. Please investigate further to ensure the deletion was not due to malicious activity or an improperly configured change.',
                'UpdatedBy': functionName
            },
            RecordState='ARCHIVED'
        )
        print(response)
    except Exception as e:
        print(e)
    # archive all findings related to resource ID
    try:
        response = securityhub.update_findings(
            Filters={'ResourceId': [{'Value': deletedResourceId,'Comparison': 'EQUALS'}]},
            Note={
                'Text': 'The resource related to this finding was identified as being deleted from AWS Config and has been archived. Please investigate further to ensure the deletion was not due to malicious activity or an improperly configured change.',
                'UpdatedBy': functionName
            },
            RecordState='ARCHIVED'
        )
        print(response)
    except Exception as e:
        print(e)