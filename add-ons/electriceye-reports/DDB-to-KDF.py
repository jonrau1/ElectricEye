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
    kdf = boto3.client('firehose')
    firehoseStream = os.environ['FIREHOSE_TARGET']
    for records in event['Records']:
        findingInfo = records['dynamodb']['NewImage']
        findingDump = json.dumps(findingInfo)
        try:
            response = kdf.put_record(DeliveryStreamName=firehoseStream,Record={'Data': findingDump})
            print(response)
        except Exception as e:
            print(e)