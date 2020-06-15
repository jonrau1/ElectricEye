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
import datetime
from auditors.Auditor import Auditor

# import boto3 clients
sts = boto3.client("sts")
kinesis = boto3.client("kinesis")
securityhub = boto3.client("securityhub")
# create env vars
awsRegion = os.environ["AWS_REGION"]
awsAccountId = sts.get_caller_identity()["Account"]
# loop through kinesis streams
response = kinesis.list_streams(Limit=100)
myKinesisStreams = response["StreamNames"]


class KinesisStreamEncryptionCheck(Auditor):
    def execute(self):
        for streams in myKinesisStreams:
            response = kinesis.describe_stream(StreamName=streams)
            streamArn = str(response["StreamDescription"]["StreamARN"])
            streamName = str(response["StreamDescription"]["StreamName"])
            streamEncryptionCheck = str(response["StreamDescription"]["EncryptionType"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            if streamEncryptionCheck == "NONE":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": streamArn + "/kinesis-streams-encryption-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": streamArn,
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
                    "Title": "[Kinesis.1] Kinesis Data Streams should be encrypted",
                    "Description": "Kinesis data stream "
                    + streamName
                    + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide",
                            "Url": "https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisStream",
                            "Id": streamArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"StreamName": streamName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": streamArn + "/kinesis-streams-encryption-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": streamArn,
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
                    "Title": "[Kinesis.1] Kinesis Data Streams should be encrypted",
                    "Description": "Kinesis data stream "
                    + streamName
                    + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Kinesis Data Stream encryption refer to the How Do I Get Started with Server-Side Encryption? section of the Amazon Kinesis Data Streams Developer Guide",
                            "Url": "https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsKinesisStream",
                            "Id": streamArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"StreamName": streamName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding


class KinesisEnhancedMonitoringCheck(Auditor):
    def execute(self):
        for streams in myKinesisStreams:
            response = kinesis.describe_stream(StreamName=streams)
            streamArn = str(response["StreamDescription"]["StreamARN"])
            streamName = str(response["StreamDescription"]["StreamName"])
            streamEnhancedMonitoring = response["StreamDescription"][
                "EnhancedMonitoring"
            ]
            for enhancedmonitors in streamEnhancedMonitoring:
                shardLevelMetricCheck = str(enhancedmonitors["ShardLevelMetrics"])
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                if shardLevelMetricCheck == "[]":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": streamArn + "/kinesis-streams-enhanced-monitoring-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": streamArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured",
                        "Description": "Kinesis data stream "
                        + streamName
                        + " does not have detailed monitoring configured, detailed monitoring allows shard-level metrics to be delivered every minute at additional cost. Business-critical streams should be considered for this configuration. Refer to the remediation instructions for information on this configuration",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide",
                                "Url": "https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsKinesisStream",
                                "Id": streamArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {"Other": {"StreamName": streamName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-3",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 IR-5",
                                "NIST SP 800-53 IR-8",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.7",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": streamArn + "/kinesis-streams-enhanced-monitoring-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": streamArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Kinesis.2] Business-critical Kinesis Data Streams should have detailed monitoring configured",
                        "Description": "Kinesis data stream "
                        + streamName
                        + " has detailed monitoring configured.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Kinesis Data Stream enhanced monitoring refer to the Monitoring the Amazon Kinesis Data Streams Service with Amazon CloudWatch section of the Amazon Kinesis Data Streams Developer Guide",
                                "Url": "https://docs.aws.amazon.com/streams/latest/dev/monitoring-with-cloudwatch.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsKinesisStream",
                                "Id": streamArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {"Other": {"StreamName": streamName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-3",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 IR-5",
                                "NIST SP 800-53 IR-8",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.7",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
