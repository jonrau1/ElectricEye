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
import json
from check_register import CheckRegister
import base64

registry = CheckRegister()

def list_topics(cache, session):
    sns = session.client("sns")
    response = cache.get("list_topics")
    if response:
        return response
    cache["list_topics"] = sns.list_topics()
    return cache["list_topics"]

@registry.register_check("sns")
def sns_topic_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SNS.1] SNS topics should be encrypted"""
    sns = session.client("sns")
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for topic in list_topics(cache, session)["Topics"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(topic,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            f"arn:{awsPartition}:sns:{awsRegion}:{awsAccountId}:", ""
        )
        response = sns.get_topic_attributes(TopicArn=topicarn)
        try:
            # this is a passing check
            encryptionCheck = str(response["Attributes"]["KmsMasterKeyId"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-topic-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsSnsTopic": {
                                "TopicName": topicName,
                                'KmsMasterKeyId': encryptionCheck
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-topic-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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

@registry.register_check("sns")
def sns_http_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SNS.2] SNS topics should not use HTTP subscriptions"""
    sns = session.client("sns")
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for topic in list_topics(cache, session)["Topics"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(topic,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            f"arn:{awsPartition}:sns:{awsRegion}:{awsAccountId}:", ""
        )
        response = sns.list_subscriptions_by_topic(TopicArn=topicarn)
        mySubs = response["Subscriptions"]
        for subscriptions in mySubs:
            subProtocol = str(subscriptions["Protocol"])
            if subProtocol == "http":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": topicarn + "/sns-http-subscription-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Application Integration",
                        "AssetService": "Amazon Simple Notification Service",
                        "AssetComponent": "Topic"
                    },
                    "Resources": [
                        {
                            "Type": "AwsSnsTopic",
                            "Id": topicarn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": topicarn + "/sns-http-subscription-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Application Integration",
                        "AssetService": "Amazon Simple Notification Service",
                        "AssetComponent": "Topic"
                    },
                    "Resources": [
                        {
                            "Type": "AwsSnsTopic",
                            "Id": topicarn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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

@registry.register_check("sns")
def sns_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SNS.3] SNS topics should not allow public or unauthenticated access"""
    sns = session.client("sns")
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for topic in list_topics(cache, session)["Topics"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(topic,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            f"arn:{awsPartition}:sns:{awsRegion}:{awsAccountId}:", ""
        )
        response = sns.get_topic_attributes(TopicArn=topicarn)
        statement_json = response["Attributes"]["Policy"]
        statement = json.loads(statement_json)
        fail = False
        # this results in one finding per topic instead of one finding per statement
        for sid in statement["Statement"]:
            if sid["Principal"] == "*":
                access = "*"
            else:
                access = sid["Principal"].get("AWS", None)
            if access != "*" or (access == "*" and "Condition" in sid):
                continue
            else:
                fail = True
                break
        if not fail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "Confidence": 75,  # The Condition may not effectively limit access
                "Title": "[SNS.3] SNS topics should not allow public or unauthenticated access",
                "Description": "SNS topic "
                + topicName
                + " does not have public access or limited by a Condition. Refer to the remediation instructions to review sns access policy",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SNS Access Policy Best Practices refer to Amazons Best Practice rules for Amazon SNS.",
                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible",
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
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "Title": "[SNS.3] SNS topics should not allow public or unauthenticated access",
                "Description": "SNS topic "
                + topicName
                + " has public access. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SNS Access Policy Best Practices refer to Amazons Best Practice rules for Amazon SNS.",
                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#ensure-topics-not-publicly-accessible",
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
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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

@registry.register_check("sns")
def sns_cross_account_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SNS.4] SNS topics should not allow cross-account access"""
    sns = session.client("sns")
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for topic in list_topics(cache, session)["Topics"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(topic,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        topicarn = str(topic["TopicArn"])
        topicName = topicarn.replace(
            f"arn:{awsPartition}:sns:{awsRegion}:{awsAccountId}:", ""
        )
        response = sns.get_topic_attributes(TopicArn=topicarn)
        myPolicy_json = str(response["Attributes"]["Policy"])
        myPolicy = json.loads(myPolicy_json)
        fail = False
        for statement in myPolicy["Statement"]:
            if statement["Principal"] == "*":
                continue
            else:
                principal = statement["Principal"].get("AWS", None)
            if principal:
                if not principal.isdigit():
                    # This assumes if it is not a digit that it must be an arn.
                    # not sure if this is a safe assumption.
                    try:
                        principal = principal.split(":")[4]
                    except IndexError:
                        continue
                if principal == awsAccountId:
                    continue
                else:
                    fail = True
                    break
        if not fail:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-cross-account-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "Title": "[SNS.4] SNS topics should not allow cross-account access",
                "Description": "SNS topic "
                + topicName
                + " does not have cross-account access.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SNS best practices refer to the Amazon SNS security best practices section of the Amazon Simple Notification Service Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
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
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": topicarn + "/sns-cross-account-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
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
                "Title": "[SNS.4] SNS topics should not allow cross-account access",
                "Description": "SNS topic " + topicName + " has cross-account access.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SNS best practices refer to the Amazon SNS security best practices section of the Amazon Simple Notification Service Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html#enforce-encryption-data-in-transit",
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
                    "AssetService": "Amazon Simple Notification Service",
                    "AssetComponent": "Topic"
                },
                "Resources": [
                    {
                        "Type": "AwsSnsTopic",
                        "Id": topicarn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSnsTopic": {"TopicName": topicName}},
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