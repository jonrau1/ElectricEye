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

from check_register import CheckRegister
import datetime
import base64
import json

registry = CheckRegister()

def list_queues(cache, session):
    response = cache.get("list_queues")
    if response:
        return response
    
    sqs = session.client("sqs")
    
    queuesWithAttributes = []

    for q in sqs.list_queues()["QueueUrls"]:
        queueUrl = q
        queueName = queueUrl.rsplit("/", 1)[-1]
        attributes = sqs.get_queue_attributes(
            QueueUrl=queueUrl, AttributeNames=["All"]
        )["Attributes"]
        # Assemble the URL, Name and Attributes into a new Dict
        queuePayload = {
            "QueueUrl": queueUrl,
            "QueueName": queueName,
            "Attributes": attributes
        }

        queuesWithAttributes.append(queuePayload)


    cache["list_queues"] = queuesWithAttributes
    return cache["list_queues"]

@registry.register_check("sqs")
def sqs_old_message_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SQS.1] Amazon Simple Queue Service (SQS) messages should not be older than 80 percent of message retention"""
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for queue in list_queues(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(queue,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        queueName = queue["QueueName"]
        messageRetention = queue["Attributes"]["MessageRetentionPeriod"]
        queueArn = queue["Attributes"]["QueueArn"]
        # Evaluate metrics
        metricResponse = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/SQS",
                            "MetricName": "ApproximateAgeOfOldestMessage",
                            "Dimensions": [{"Name": "QueueName", "Value": queueName}]
                        },
                        "Period": 3600,
                        "Stat": "Maximum",
                        "Unit": "Seconds"
                    }
                }
            ],
            StartTime=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
            EndTime=datetime.datetime.now(datetime.timezone.utc)
        )
        metrics = metricResponse["MetricDataResults"]
        counter = 0
        fail = False
        for metric in metrics:
            for value in metric["Values"]:
                if value > int(messageRetention) * 0.8:
                    counter += 1
                if counter > 2:
                    fail = True
                    break
        # this is a passing check
        if not fail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": queueArn + "/sqs-old-message-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": queueArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SQS.1] Amazon Simple Queue Service (SQS) messages should not be older than 80 percent of message retention",
                "Description": f"Amazon Simple Queue Service (SQS) queue {queueName} has not had at least 3 messages waiting for longer than 80 percent of the message retention.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Queue Service",
                    "AssetComponent": "Queue"
                },
                "Resources": [
                    {
                        "Type": "AwsSqsQueue",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": queueArn + "/sqs-old-message-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": queueArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SQS.1] Amazon Simple Queue Service (SQS) messages should not be older than 80 percent of message retention",
                "Description": "Amazon Simple Queue Service (SQS) queue "
                + queueName
                + " has had at least 3 messages waiting for longer than 80 percent of the message retention.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Queue Service",
                    "AssetComponent": "Queue"
                },
                "Resources": [
                    {
                        "Type": "AwsSqsQueue",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("sqs")
def sqs_queue_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SQS.2] Amazon Simple Queue Service (SQS) queues should use server side encryption"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for queue in list_queues(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(queue,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        queueName = queue["QueueName"]
        queueArn = queue["Attributes"]["QueueArn"]
        queueEncryption=queue["Attributes"].get("KmsMasterKeyId")
        # this is a failing check
        if queueEncryption is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{queueArn}/sqs-queue-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{queueArn}/sqs-queue-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SQS.2] Amazon Simple Queue Service (SQS) queues should use server side encryption",
                "Description": f"Amazon Simple Queue Service (SQS) queue {queueName} has not enabled Server side encryption. Server-side encryption (SSE) lets you transmit sensitive data in encrypted queues. SSE protects the contents of messages in queues using SQS-managed encryption keys (SSE-SQS) or keys managed in the AWS Key Management Service (SSE-KMS). SSE encrypts messages as soon as Amazon SQS receives them. The messages are stored in encrypted form and Amazon SQS decrypts messages only when they are sent to an authorized consumer. An encrypted queue that uses the default key (AWS managed KMS key for Amazon SQS) cannot invoke a Lambda function in a different AWS account. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for encryption of SQS queues, refer to the Data Encryption section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Queue Service",
                    "AssetComponent": "Queue"
                },
                "Resources": [
                    {
                        "Type": "AwsSqsQueue",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.PT-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{queueArn}/sqs-queue-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{queueArn}/sqs-queue-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SQS.2] Amazon Simple Queue Service (SQS) queues should use server side encryption",
                "Description": f"Amazon Simple Queue Service (SQS) queue {queueName} has enabled Server side encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on best practices for encryption of SQS queues, refer to the Data Encryption section of the Amazon SQS Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Queue Service",
                    "AssetComponent": "Queue"
                },
                "Resources": [
                    {
                        "Type": "AwsSqsQueue",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.PT-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("sqs")
def sqs_queue_public_accessibility_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SQS.3] Amazon Simple Queue Service (SQS) queues should not be unconditionally open to the public"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for queue in list_queues(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(queue,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        queueName = queue["QueueName"]
        queueArn = queue["Attributes"]["QueueArn"]
        # set the Bool for the Queue not being public, override it in the event it IS public or if there is not a policy
        queueIsPublic = False
        try:
            queuePolicy=json.loads(queue["Attributes"]["Policy"])
            for statement in queuePolicy["Statement"]:
                if statement["Effect"] == "Allow":
                    if statement.get("Principal") == "*":
                        if statement.get("Condition") is None: 
                            queueIsPublic = True
        except KeyError:
            queueIsPublic = True
        # this is a failing function
        if queueIsPublic is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{queueArn}/sqs-queue-access-policy-allows-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{queueArn}/sqs-queue-access-policy-allows-public-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[SQS.3] Amazon Simple Queue Service (SQS) queues should not be unconditionally open to the public",
                "Description": f"Amazon Simple Queue Service (SQS) queue {queueName} either does not define an access policy or it is unconditionally open to the public. The access policy defines the accounts, users and roles that can access this queue, and the actions that are allowed. You can configure basic and advanced settings. In the basic settings, you configure who can send messages to the queue, and who can receive messages from the queue. The read-only JSON panel displays the resulting access policy for the queue. By default, only the queue owner can send and receive messages. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring access policies refer to the Identity and access management in Amazon SQS section of the Amazon Simple Queue Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Queue Service",
                    "AssetComponent": "Queue"
                },
                "Resources": [
                    {
                        "Type": "AwsSqsQueue",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding