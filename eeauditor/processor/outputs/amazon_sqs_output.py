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

import tomli
import boto3
import sys
import os
import json
from base64 import b64decode
#from hashlib import new as hasher
from botocore.exceptions import ClientError
from processor.outputs.output_base import ElectricEyeOutput

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "amazon_sqs"

    def __init__(self):
        print("Preparing Amazon SQS output.")

        if os.environ["TOML_FILE_PATH"] == "None":
            # Get the absolute path of the current directory
            currentDir = os.path.abspath(os.path.dirname(__file__))
            # Go two directories back to /eeauditor/
            twoBack = os.path.abspath(os.path.join(currentDir, "../../"))
            # TOML is located in /eeauditor/ directory
            tomlFile = f"{twoBack}/external_providers.toml"
        else:
            tomlFile = os.environ["TOML_FILE_PATH"]

        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Variable for the entire [outputs.amazon_sqs] section
        sqsDetails = data["outputs"]["amazon_sqs"]

        queueUrl = sqsDetails["amazon_sqs_queue_url"]
        queueBatchSize = sqsDetails["amazon_sqs_batch_size"]
        awsRegion = sqsDetails["amazon_sqs_queue_region"]

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not all(s for s in [queueUrl, queueBatchSize, awsRegion]):
            print("An empty value was detected in '[outputs.amazon_sqs]'. Review the TOML file and try again!")
            sys.exit(2)

        self.queueUrl = queueUrl
        self.queueBatchSize = queueBatchSize
        self.sqs = boto3.client("sqs", region_name=awsRegion)

    def write_findings(self, findings: list, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write to Amazon SQS!")
            exit(0)

        print(f"Sending {len(findings)} findings to Amazon SQS in {self.queueBatchSize}-message batches.")

        # Unfold the AssetDetails
        decodedFindings = [
            {**d, "ProductFields": {**d["ProductFields"],
                "AssetDetails": json.loads(b64decode(d["ProductFields"]["AssetDetails"]).decode("utf-8"))
                    if d["ProductFields"]["AssetDetails"] is not None
                    else None
            }} if "AssetDetails" in d["ProductFields"]
            else d
            for d in findings
        ]

        del findings

        for i in range(0, len(decodedFindings), self.queueBatchSize):
            batch = (decodedFindings[i : i + self.queueBatchSize])
            # Send to SQS
            self.send_message_to_sqs(batch)

        print(f"Done sending all findings to Amazon SQS!")
    
    '''
    # This was meant for using the BatchSendMessage API which requires a message ID for each of the messages in a batch
    # may make use of it...eventually? Uncomment the import statement above in case

    def create_hashed_message_id(self, findingId):
        """
        Returns a SHA-1 hexdigest of no more than 80 characters from the "Id" of ASFF to use as a SQS MessageId
        """
        # Create the SHA1 hash object from the bytes of 'findingId' parsed from a finding
        # and retrieve the digest
        hashFinding = hasher("sha1").update(findingId.encode("utf-8")).hexdigest()
                
        # Truncate the hash if it exceeds 80 characters
        if len(hashFinding) > 80:
            hashFinding = hashFinding[:80]
        
        return hashFinding
    '''

    def send_message_to_sqs(self, batch):
        """
        Writes batches of ASFF findings into SQS
        """
        sqs = self.sqs

        for entry in batch:
            try:
                sqs.send_message(
                    QueueUrl=self.queueUrl,
                    MessageBody=json.dumps(entry),
                    DelaySeconds=1
                )
            except ClientError as ce:
                print(f"Batch failed due to: {ce}, continuing to the next.")
                continue