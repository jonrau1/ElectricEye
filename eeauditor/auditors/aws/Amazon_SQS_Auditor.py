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

import datetime
from dateutil import parser

import boto3
import json

from check_register import CheckRegister

registry = CheckRegister()
sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")


def list_queues(cache):
    response = cache.get("list_queues")
    if response:
        return response
    cache["list_queues"] = sqs.list_queues()
    return cache["list_queues"]


@registry.register_check("sqs")
def sqs_old_message_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_queues(cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'QueueUrls' in response:
        for queueUrl in response["QueueUrls"]:
            queueName = queueUrl.rsplit("/", 1)[-1]
            attributes = sqs.get_queue_attributes(
                QueueUrl=queueUrl, AttributeNames=["MessageRetentionPeriod", "QueueArn"]
            )
            messageRetention = attributes["Attributes"]["MessageRetentionPeriod"]
            queueArn = attributes["Attributes"]["QueueArn"]
            metricResponse = cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/SQS",
                                "MetricName": "ApproximateAgeOfOldestMessage",
                                "Dimensions": [{"Name": "QueueName", "Value": queueName}],
                            },
                            "Period": 3600,
                            "Stat": "Maximum",
                            "Unit": "Seconds",
                        },
                    },
                ],
                StartTime=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1),
                EndTime=datetime.datetime.now(datetime.timezone.utc),
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
                    "Title": "[SQS.1] SQS messages should not be older than 80 percent of message retention",
                    "Description": "SQS queue "
                    + queueName
                    + " has not had at least 3 messages waiting for longer than 80 percent of the message retention.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF ID.AM-2",
                            "NIST SP 800-53 CM-8",
                            "NIST SP 800-53 PM-5",
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
                    "Title": "[SQS.1] SQS messages should not be older than 80 percent of message retention",
                    "Description": "SQS queue "
                    + queueName
                    + " has had at least 3 messages waiting for longer than 80 percent of the message retention.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for SQS queue messages refer to the Quotas related to messages section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html#quotas-messages",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF ID.AM-2",
                            "NIST SP 800-53 CM-8",
                            "NIST SP 800-53 PM-5",
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
    else: 
        # No queues listed
        pass

@registry.register_check("sqs")
def sqs_queue_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_queues(cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'QueueUrls' in response:
        for queueUrl in response["QueueUrls"]:
            queueName = queueUrl.rsplit("/", 1)[-1]
            attributes = sqs.get_queue_attributes(
                QueueUrl=queueUrl, AttributeNames=["QueueArn", "KmsMasterKeyId"]
            )
            queueArn=attributes["Attributes"]["QueueArn"]
            queueEncryption=attributes["Attributes"].get('KmsMasterKeyId')

            if queueEncryption != None:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": queueArn + "/sqs_queue_encryption_check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": queueArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[SQS.2] SQS queues should use Server Side encryption",
                    "Description": f"SQS queue {queueName} has Server Side encryption enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for encryption of SQS queues, refer to the Data Encryption section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsSqsQueue",
                            "Id": queueArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsSqsQueue": {
                                    "QueueName": queueName,
                                    "KmsMasterKeyId": str(queueEncryption)
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3"
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": queueArn + "/sqs_queue_encryption_check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": queueArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[SQS.2] SQS queues should use server side encryption",
                    "Description": f"SQS queue {queueName} has not enabled Server side encryption.  Refer to the recommendations to remediate.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for encryption of SQS queues, refer to the Data Encryption section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF PR.DS-1",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
    else: 
        # No queues listed
        pass

@registry.register_check("sqs")
def sqs_queue_public_accessibility_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_queues(cache)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'QueueUrls' in response:
        for queueUrl in response["QueueUrls"]:
            queueName = queueUrl.rsplit("/", 1)[-1]
            attributes = sqs.get_queue_attributes(
                QueueUrl=queueUrl, AttributeNames=["QueueArn", "Policy"]
            )
            queueArn=attributes["Attributes"]["QueueArn"]
            queuePolicy=json.loads(attributes["Attributes"]["Policy"])

            accessibility = "not_public"

            for statement in queuePolicy["Statement"]:
                if statement["Effect"] == 'Allow':
                    if statement.get("Principal") == '*':
                        if statement.get('Condition') == None: 
                            accessibility = "public"

            if accessibility == "not_public":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": queueArn + "/sqs_queue_public_accessibility_check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": queueArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[SQS.3] SQS queues should not be unconditionally open to the public",
                    "Description": f"SQS queue {queueName} is not unconditionally open to the public.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for SQS Policies, refer to the Identity and Access Management section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.amazonaws.cn/en_us/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsSqsQueue",
                            "Id": queueArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsSqsQueue": {"QueueName": queueName}}
                        },
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            
            else: 
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": queueArn + "/sqs_queue_public_accessibility_check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": queueArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[SQS.3] SQS queues should not be unconditionally open to the public",
                    "Description": f"SQS queue {queueName} is unconditionally open to the public.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for SQS Policies, refer to the Identity and Access Management section of the Amazon SQS Developer Guide",
                            "Url": "https://docs.amazonaws.cn/en_us/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-authentication-and-access-control.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF PR.AC-4",
                            "NIST CSF PR.DS-5",
                            "NIST CSF PR.PT-3",
                            "NIST SP 800-53 AC-1"
                            "NIST SP 800-53 AC-3"
                            "NIST SP 800-53 AC-17"
                            "NIST SP 800-53 AC-22"
                            "ISO 27001:2013 A.13.1.2"
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
            yield finding
    else:
        # No queues listed
        pass