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

import datetime
from check_register import CheckRegister

registry = CheckRegister()

# loop through Firehose delivery streams
def list_delivery_streams(cache, session):
    firehose = session.client("firehose")
    response = cache.get("list_delivery_streams")
    if response:
        return response
    cache["list_delivery_streams"] = firehose.list_delivery_streams(Limit=100)
    return cache["list_delivery_streams"]

@registry.register_check("firehose")
def firehose_delivery_stream_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Firehose.1] AWS Kinesis Firehose delivery streams should be encrypted"""
    firehose = session.client("firehose")
    response = list_delivery_streams(cache, session)
    myFirehoseStreams = response["DeliveryStreamNames"]
    for deliverystreams in myFirehoseStreams:
        firehoseName = str(deliverystreams)
        try:
            response = firehose.describe_delivery_stream(DeliveryStreamName=firehoseName)
            # Pull ARN and check for Encryption
            firehoseArn = str(response["DeliveryStreamDescription"]["DeliveryStreamARN"])
            firehoseEncryptionCheck = str(response["DeliveryStreamDescription"]["DeliveryStreamEncryptionConfiguration"]["Status"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if firehoseEncryptionCheck == "DISABLED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": firehoseArn + "/firehose-stream-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": firehoseArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[Firehose.1] AWS Kinesis Firehose delivery streams should be encrypted",
                    "Description": "AWS Kinesis Firehose delivery stream "
                    + firehoseName
                    + " is not encrypted. If you send data to your delivery stream using PutRecord or PutRecordBatch, or if you send the data using AWS IoT, Amazon CloudWatch Logs, or CloudWatch Events, you can turn on server-side encryption by using the StartDeliveryStreamEncryption operation. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Firehose encryption refer to the Data Protection in Amazon Kinesis Data Firehose section of the Amazon Kinesis Data Firehose Developer Guide",
                            "Url": "https://docs.aws.amazon.com/firehose/latest/dev/encryption.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisFirehoseDeliveryStream",
                            "Id": firehoseArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"deliveryStreamName": firehoseName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            elif firehoseEncryptionCheck == "ENABLED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": firehoseArn + "/firehose-stream-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": firehoseArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Firehose.1] AWS Kinesis Firehose delivery streams should be encrypted",
                    "Description": "AWS Kinesis Firehose delivery stream "
                    + firehoseName
                    + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Firehose encryption refer to the Data Protection in Amazon Kinesis Data Firehose section of the Amazon Kinesis Data Firehose Developer Guide",
                            "Url": "https://docs.aws.amazon.com/firehose/latest/dev/encryption.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisFirehoseDeliveryStream",
                            "Id": firehoseArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"deliveryStreamName": firehoseName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                pass
        except Exception as e:
            print(e)