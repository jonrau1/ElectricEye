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

def list_brokers(cache, session):
    amzmq = session.client("mq")
    response = cache.get("list_brokers")
    if response:
        return response
    cache["list_brokers"] = amzmq.list_brokers(MaxResults=100)
    return cache["list_brokers"]

@registry.register_check("mq")
def broker_kms_cmk_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption"""
    amzmq = session.client("mq")
    response = list_brokers(cache, session)
    myBrokers = response["BrokerSummaries"]
    for broker in myBrokers:
        brokerName = str(broker["BrokerName"])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response["BrokerArn"])
            brokerId = str(response["BrokerId"])
            kmsCmkCheck = str(response["EncryptionOptions"]["UseAwsOwnedKey"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if kmsCmkCheck == "True":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-broker-kms-cmk-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " does not use a customer-managed KMS CMK for encryption. Customer managed CMKs are CMKs in your AWS account that you create, own, and manage. You have full control over these CMKs, including establishing and maintaining their key policies, IAM policies, and grants, enabling and disabling them, rotating their cryptographic material, adding tags, creating aliases that refer to the CMK, and scheduling the CMKs for deletion. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on encryption at rest considerations for Amazon MQ refer to the Encryption at Rest section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-encryption.html#encryption-at-rest",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
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
            else:
                kmsKeyId = str(response["EncryptionOptions"]["KmsKeyId"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-broker-kms-cmk-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " uses a customer-managed KMS CMK for encryption.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on encryption at rest considerations for Amazon MQ refer to the Encryption at Rest section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-encryption.html#encryption-at-rest",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "BrokerName": brokerName,
                                    "BrokerId": brokerId,
                                    "kmsKeyId": kmsKeyId,
                                }
                            },
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
        except Exception as e:
            print(e)

@registry.register_check("mq")
def broker_audit_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled"""
    amzmq = session.client("mq")
    response = list_brokers(cache, session)
    myBrokers = response["BrokerSummaries"]
    for broker in myBrokers:
        brokerName = str(broker["BrokerName"])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response["BrokerArn"])
            brokerId = str(response["BrokerId"])
            auditLogCheck = str(response["Logs"]["Audit"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if auditLogCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-broker-audit-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " does not have audit logging enabled. Audit logging enables logging of management actions taken using JMX or using the ActiveMQ Web Console and publishes audit.log to a log group in CloudWatch. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-8",
                            "NIST SP 800-53 Rev. 4 SI-4",
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
                    "Id": brokerArn + "/amazonmq-broker-audit-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled",
                    "Description": "AmazonMQ broker " + brokerName + " has audit logging enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-8",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("mq")
def broker_general_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled"""
    amzmq = session.client("mq")
    response = list_brokers(cache, session)
    myBrokers = response["BrokerSummaries"]
    for broker in myBrokers:
        brokerName = str(broker["BrokerName"])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response["BrokerArn"])
            brokerId = str(response["BrokerId"])
            genLogCheck = str(response["Logs"]["General"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if genLogCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-broker-general-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " does not have general logging enabled. General logging enables the default INFO logging level (DEBUG logging isnt supported) and publishes activemq.log to a log group in CloudWatch. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-8",
                            "NIST SP 800-53 Rev. 4 SI-4",
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
                    "Id": brokerArn + "/amazonmq-broker-general-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " has general logging enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker logging refer to the Understanding the Structure of Logging in CloudWatch Logs section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-configuring-cloudwatch-logs.html#structure-of-logging-cloudwatch-logs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-8",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.7",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("mq")
def broker_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible"""
    amzmq = session.client("mq")
    response = list_brokers(cache, session)
    myBrokers = response["BrokerSummaries"]
    for broker in myBrokers:
        brokerName = str(broker["BrokerName"])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response["BrokerArn"])
            brokerId = str(response["BrokerId"])
            publicAccessCheck = str(response["PubliclyAccessible"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if publicAccessCheck == "True":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-public-accessible-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "CRITICAL"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " is publicly accessible. Brokers created without public accessibility cannot be accessed from outside of your VPC. This greatly reduces your susceptibility to Distributed Denial of Service (DDoS) attacks from the public internet. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker accessibility through a VPC refer to the Accessing the ActiveMQ Web Console of a Broker without Public Accessibility section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/accessing-web-console-of-broker-without-private-accessibility.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-3",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-17",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-20",
                            "NIST SP 800-53 Rev. 4 SC-15",
                            "AICPA TSC CC6.6",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-public-accessible-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
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
                    "Title": "[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " is not publicly accessible.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker accessibility through a VPC refer to the Accessing the ActiveMQ Web Console of a Broker without Public Accessibility section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/accessing-web-console-of-broker-without-private-accessibility.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-3",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-17",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-20",
                            "NIST SP 800-53 Rev. 4 SC-15",
                            "AICPA TSC CC6.6",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("mq")
def broker_minor_version_auto_upgrade_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version"""
    amzmq = session.client("mq")
    response = list_brokers(cache, session)
    myBrokers = response["BrokerSummaries"]
    for broker in myBrokers:
        brokerName = str(broker["BrokerName"])
        try:
            response = amzmq.describe_broker(BrokerId=brokerName)
            brokerArn = str(response["BrokerArn"])
            brokerId = str(response["BrokerId"])
            autoUpgrMinorVersionCheck = str(response["AutoMinorVersionUpgrade"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if autoUpgrMinorVersionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-auto-minor-version-upgrade-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " is not configured to automatically upgrade to the latest minor version. To upgrade the broker to new versions as AWS releases them, choose Enable automatic minor version upgrades. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker auto upgrades refer to the Tutorial: Editing Broker Engine Version, Instance Type, CloudWatch Logs, and Maintenance Preferences section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-editing-broker-preferences.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 MA-2",
                            "NIST SP 800-53 Rev. 4 MA-3",
                            "NIST SP 800-53 Rev. 4 MA-5",
                            "NIST SP 800-53 Rev. 4 MA-6",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.11.1.2",
                            "ISO 27001:2013 A.11.2.4",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.6"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": brokerArn + "/amazonmq-auto-minor-version-upgrade-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version",
                    "Description": "AmazonMQ broker "
                    + brokerName
                    + " is configured to automatically upgrade to the latest minor version.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on message broker auto upgrades refer to the Tutorial: Editing Broker Engine Version, Instance Type, CloudWatch Logs, and Maintenance Preferences section of the Amazon MQ Developer Guide",
                            "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-editing-broker-preferences.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId,}
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 MA-2",
                            "NIST SP 800-53 Rev. 4 MA-3",
                            "NIST SP 800-53 Rev. 4 MA-5",
                            "NIST SP 800-53 Rev. 4 MA-6",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.11.1.2",
                            "ISO 27001:2013 A.11.2.4",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.6"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except Exception as e:
            print(e)