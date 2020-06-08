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
import json
import os
import boto3

# import boto3 clients
securityhub = boto3.client("securityhub")
sns = boto3.client("sns")
sts = boto3.client("sts")
# create account id & region variables
awsAccountId = sts.get_caller_identity()["Account"]
awsRegion = os.environ["AWS_REGION"]
# loop through SNS topics
response = sns.list_topics()
mySnsTopics = response["Topics"]


def sns_topic_encryption_check():
    for topic in mySnsTopics:
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            "arn:aws:sns:" + awsRegion + ":" + awsAccountId + ":", ""
        )
        response = sns.get_topic_attributes(TopicArn=topicarn)
        try:
            # this is a passing check
            encryptionCheck = str(response["Attributes"]["KmsMasterKeyId"])
            try:
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            "SchemaVersion": "2018-10-08",
                            "Id": topicarn + "/sns-topic-encryption-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
                            "GeneratorId": topicarn,
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
                            "Title": "[SNS.1] SNS topics should be encrypted",
                            "Description": "SNS topic " + topicName + " is encrypted.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on SNS encryption at rest and how to configure it refer to the Encryption at Rest section of the Amazon Simple Notification Service Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsSnsTopic",
                                    "Id": topicarn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsSnsTopic": {"TopicName": topicName}
                                    },
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
                    ]
                )
                print(response)
            except Exception as e:
                print(e)
        except:
            try:
                iso8601Time = (
                    datetime.datetime.utcnow()
                    .replace(tzinfo=datetime.timezone.utc)
                    .isoformat()
                )
                response = securityhub.batch_import_findings(
                    Findings=[
                        {
                            "SchemaVersion": "2018-10-08",
                            "Id": topicarn + "/sns-topic-encryption-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
                            "GeneratorId": topicarn,
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
                            "Title": "[SNS.1] SNS topics should be encrypted",
                            "Description": "SNS topic "
                            + topicName
                            + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on SNS encryption at rest and how to configure it refer to the Encryption at Rest section of the Amazon Simple Notification Service Developer Guide.",
                                    "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsSnsTopic",
                                    "Id": topicarn,
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsSnsTopic": {"TopicName": topicName}
                                    },
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
                    ]
                )
                print(response)
            except Exception as e:
                print(e)


def sns_http_subscription_check():
    for topic in mySnsTopics:
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            "arn:aws:sns:" + awsRegion + ":" + awsAccountId + ":", ""
        )
        response = sns.list_subscriptions_by_topic(TopicArn=topicarn)
        mySubs = response["Subscriptions"]
        for subscriptions in mySubs:
            subProtocol = str(subscriptions["Protocol"])
            if subProtocol == "http":
                try:
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                "SchemaVersion": "2018-10-08",
                                "Id": topicarn + "/sns-http-subscription-check",
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": topicarn,
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
                                "Title": "[SNS.2] SNS topics should not use HTTP subscriptions",
                                "Description": "SNS topic "
                                + topicName
                                + " has a HTTP subscriber. Refer to the remediation instructions to remediate this behavior",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on SNS encryption in transit refer to the Enforce Encryption of Data in Transit section of the Amazon Simple Notification Service Developer Guide.",
                                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsSnsTopic",
                                        "Id": topicarn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsSnsTopic": {"TopicName": topicName}
                                        },
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
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)
            else:
                try:
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    response = securityhub.batch_import_findings(
                        Findings=[
                            {
                                "SchemaVersion": "2018-10-08",
                                "Id": topicarn + "/sns-http-subscription-check",
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
                                "GeneratorId": topicarn,
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
                                "Title": "[SNS.2] SNS topics should not use HTTP subscriptions",
                                "Description": "SNS topic "
                                + topicName
                                + " does not have a HTTP subscriber.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on SNS encryption in transit refer to the Enforce Encryption of Data in Transit section of the Amazon Simple Notification Service Developer Guide.",
                                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsSnsTopic",
                                        "Id": topicarn,
                                        "Partition": "aws",
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsSnsTopic": {"TopicName": topicName}
                                        },
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
                        ]
                    )
                    print(response)
                except Exception as e:
                    print(e)


def sns_cross_account_check():
    for topic in mySnsTopics:
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            "arn:aws:sns:" + awsRegion + ":" + awsAccountId + ":", ""
        )
        response = sns.get_topic_attributes(TopicArn=topicarn)
        myPolicy_json = str(response["Attributes"]["Policy"])
        myPolicy = json.loads(myPolicy_json)
        for statement in myPolicy["Statement"]:
            principal = statement["Principal"]["AWS"]
            if principal[0] != "*":
                if not principal[0].isdigit():
                    principal = principal.split(":")[4]
                if principal == awsAccountId:
                    try:
                        iso8601Time = (
                            datetime.datetime.utcnow()
                            .replace(tzinfo=datetime.timezone.utc)
                            .isoformat()
                        )
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": topicarn + "/sns-cross-account-check",
                                    "ProductArn": "arn:aws:securityhub:"
                                    + awsRegion
                                    + ":"
                                    + awsAccountId
                                    + ":product/"
                                    + awsAccountId
                                    + "/default",
                                    "GeneratorId": topicarn,
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
                                    "Title": "[SNS.3] SNS topics should not allow cross-account access",
                                    "Description": "SNS topic "
                                    + topicName
                                    + " does not have cross-account access.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SNS best practices refer to the Amazon SNS security best practices section of the Amazon Simple Notification Service Developer Guide.",
                                            "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
                                        }
                                    },
                                    "ProductFields": {"Product Name": "ElectricEye"},
                                    "Resources": [
                                        {
                                            "Type": "AwsSnsTopic",
                                            "Id": topicarn,
                                            "Partition": "aws",
                                            "Region": awsRegion,
                                            "Details": {
                                                "AwsSnsTopic": {"TopicName": topicName}
                                            },
                                        }
                                    ],
                                    "Compliance": {"Status": "PASSED"},
                                    "Workflow": {"Status": "RESOLVED"},
                                    "RecordState": "ARCHIVED",
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)
                else:
                    try:
                        iso8601Time = (
                            datetime.datetime.utcnow()
                            .replace(tzinfo=datetime.timezone.utc)
                            .isoformat()
                        )
                        response = securityhub.batch_import_findings(
                            Findings=[
                                {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": topicarn + "/sns-cross-account-check",
                                    "ProductArn": "arn:aws:securityhub:"
                                    + awsRegion
                                    + ":"
                                    + awsAccountId
                                    + ":product/"
                                    + awsAccountId
                                    + "/default",
                                    "GeneratorId": topicarn,
                                    "AwsAccountId": awsAccountId,
                                    "Types": [
                                        "Software and Configuration Checks/AWS Security Best Practices",
                                        "Effects/Data Exposure",
                                    ],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "Low"},
                                    "Confidence": 99,
                                    "Title": "[SNS.3] SNS topics should not allow cross-account access",
                                    "Description": "SNS topic "
                                    + topicName
                                    + " has cross-account access.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on SNS best practices refer to the Amazon SNS security best practices section of the Amazon Simple Notification Service Developer Guide.",
                                            "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
                                        }
                                    },
                                    "ProductFields": {"Product Name": "ElectricEye"},
                                    "Resources": [
                                        {
                                            "Type": "AwsSnsTopic",
                                            "Id": topicarn,
                                            "Partition": "aws",
                                            "Region": awsRegion,
                                            "Details": {
                                                "AwsSnsTopic": {"TopicName": topicName}
                                            },
                                        }
                                    ],
                                    "Compliance": {"Status": "Failed"},
                                    "Workflow": {"Status": "New"},
                                    "RecordState": "Active",
                                }
                            ]
                        )
                        print(response)
                    except Exception as e:
                        print(e)


def sns_auditor():
    sns_topic_encryption_check()
    sns_http_subscription_check()
    sns_cross_account_check()


sns_auditor()
