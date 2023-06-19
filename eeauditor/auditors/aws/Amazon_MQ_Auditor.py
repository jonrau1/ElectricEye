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
import os
import sys
import boto3
import requests
import ipaddress
import datetime
import base64
import json
from botocore.exceptions import ClientError
from check_register import CheckRegister

registry = CheckRegister()

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_api_key(cache):

    response = cache.get("get_shodan_api_key")
    if response:
        return response

    validCredLocations = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

    # Get the absolute path of the current directory
    currentDir = os.path.abspath(os.path.dirname(__file__))
    # Go two directories back to /eeauditor/
    twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

    # TOML is located in /eeauditor/ directory
    tomlFile = f"{twoBack}/external_providers.toml"
    with open(tomlFile, "rb") as f:
        data = tomli.load(f)

    # Parse from [global] to determine credential location of PostgreSQL Password
    credLocation = data["global"]["credentials_location"]
    shodanCredValue = data["global"]["shodan_api_key_value"]
    if credLocation not in validCredLocations:
        print(f"Invalid option for [global.credLocation]. Must be one of {str(validCredLocations)}.")
        sys.exit(2)
    if not shodanCredValue:
        apiKey = None
    else:

        # Boto3 Clients
        ssm = boto3.client("ssm")
        asm = boto3.client("secretsmanager")

        # Retrieve API Key
        if credLocation == "CONFIG_FILE":
            apiKey = shodanCredValue

        # Retrieve the credential from SSM Parameter Store
        elif credLocation == "AWS_SSM":
            
            try:
                apiKey = ssm.get_parameter(
                    Name=shodanCredValue,
                    WithDecryption=True
                )["Parameter"]["Value"]
            except ClientError as e:
                print(f"Error retrieving API Key from SSM, skipping all Shodan checks, error: {e}")
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as e:
                print(f"Error retrieving API Key from ASM, skipping all Shodan checks, error: {e}")
                apiKey = None
        
    cache["get_shodan_api_key"] = apiKey
    return cache["get_shodan_api_key"]

def google_dns_resolver(target):
    """
    Accepts a Public DNS name and attempts to use Google's DNS A record resolver to determine an IP address
    """
    url = f"https://dns.google/resolve?name={target}&type=A"
    
    r = requests.get(url=url)
    if r.status_code != 200:
        return None
    else:
        for result in json.loads(r.text)["Answer"]:
            try:
                if not (
                    ipaddress.IPv4Address(result["data"]).is_private
                    or ipaddress.IPv4Address(result["data"]).is_loopback
                    or ipaddress.IPv4Address(result["data"]).is_link_local
                ):
                    return result["data"]
                else:
                    continue
            except ipaddress.AddressValueError:
                continue
        # if the loop terminates without any result return None
        return None

def list_brokers(cache, session):
    amazonMqBrokerDetails = []

    response = cache.get("list_brokers")
    if response:
        return response
    
    amzmq = session.client("mq")
    for broker in amzmq.list_brokers(MaxResults=100)["BrokerSummaries"]:
        amazonMqBrokerDetails.append(
            amzmq.describe_broker(
                BrokerId=broker["BrokerName"]
            )
        )

    cache["list_brokers"] = amazonMqBrokerDetails
    return cache["list_brokers"]

@registry.register_check("mq")
def broker_kms_cmk_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.1] AmazonMQ message brokers should use customer-managed KMS CMKs for encryption"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        if response["EncryptionOptions"]["UseAwsOwnedKey"] is True:
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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

@registry.register_check("mq")
def broker_audit_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.2] AmazonMQ message brokers should have audit logging enabled"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        brokerName = broker["BrokerName"]
        try:
            auditLogCheck = response["Logs"]["Audit"]
        except KeyError:
            auditLogCheck = False
        if auditLogCheck is False:
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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

@registry.register_check("mq")
def broker_general_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.3] AmazonMQ message brokers should have general logging enabled"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        brokerName = broker["BrokerName"]
        genLogCheck = str(response["Logs"]["General"])
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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

@registry.register_check("mq")
def broker_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        brokerName = broker["BrokerName"]
        if response["PubliclyAccessible"] is True:
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
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[AmazonMQ.4] AmazonMQ message brokers should not be publicly accessible",
                "Description": f"AmazonMQ broker {brokerName} is publicly accessible. Brokers created without public accessibility cannot be accessed from outside of your VPC. This greatly reduces your susceptibility to Distributed Denial of Service (DDoS) attacks from the public internet and can also expose your RabbitMQ or ActiveMQ dashboards to unauthorized access. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on message broker accessibility through a VPC refer to the Accessing the ActiveMQ Web Console of a Broker without Public Accessibility section of the Amazon MQ Developer Guide",
                        "Url": "https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/accessing-web-console-of-broker-without-private-accessibility.html",
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
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("mq")
def broker_minor_version_auto_upgrade_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.5] AmazonMQ message brokers should be configured to automatically upgrade to the latest minor version"""
    amzmq = session.client("mq")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        if response["AutoMinorVersionUpgrade"] is False:
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
                "Resources": [
                    {
                        "Type": "AwsMqMessageBroker",
                        "Id": brokerArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"BrokerName": brokerName, "BrokerId": brokerId}
                        }
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Application Integration",
                    "AssetService": "Amazon MQ",
                    "AssetComponent": "Broker"
                },
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

@registry.register_check("mq")
def public_amazon_mq_broker_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AmazonMQ.6] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    amzmq = session.client("mq")
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for broker in list_brokers(cache, session):
        if shodanApiKey is None:
            continue
        # B64 encode all of the details for the Asset
        brokerId = broker["BrokerId"]
        brokerName = broker["BrokerName"]
        response = amzmq.describe_broker(BrokerId=brokerName)
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        brokerArn = response["BrokerArn"]
        if response["PubliclyAccessible"] is True:
            try:
                consoleHostname = response["BrokerInstances"][0]["ConsoleURL"].split("https://")[1].split(":")[0]
            except KeyError:
                continue
            try:
                mqBrokerIpv4 = google_dns_resolver(consoleHostname)
            except KeyError:
                continue
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{mqBrokerIpv4}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{brokerArn}/{mqBrokerIpv4}/amazon-mq-broker-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[AmazonMQ.6] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                    "Description": f"Amazon MQ message broker {brokerName} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
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
                        "AssetService": "Amazon MQ",
                        "AssetComponent": "Broker"
                    },
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId}
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                assetPayload = {
                    "Broker": response,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{brokerArn}/{mqBrokerIpv4}/amazon-mq-broker-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": brokerArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[AmazonMQ.6] Publicly accessible Amazon MQ message brokers should be monitored for being indexed by Shodan",
                    "Description": f"AmazonMQ Broker {brokerName} has been indexed on IP address {mqBrokerIpv4}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{mqBrokerIpv4}"
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
                        "AssetService": "Amazon MQ",
                        "AssetComponent": "Broker"
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Application Integration",
                        "AssetService": "Amazon MQ",
                        "AssetComponent": "Broker"
                    },
                    "Resources": [
                        {
                            "Type": "AwsMqMessageBroker",
                            "Id": brokerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"BrokerName": brokerName, "BrokerId": brokerId}
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

## END ??