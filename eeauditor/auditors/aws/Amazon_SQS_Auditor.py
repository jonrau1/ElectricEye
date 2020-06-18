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

from check_register import CheckRegister

registry = CheckRegister()
sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")


@registry.register_check("sqs")
def sqs_old_message_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = sqs.list_queues()
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
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
                        "Type": "AwsSQS",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {"Status": "PASSED",},
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
                        "Type": "AwsSQS",
                        "Id": queueArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {"Status": "FAILED"},
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
