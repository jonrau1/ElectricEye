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

import boto3
import datetime
import botocore
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
health = boto3.client("health")

@registry.register_check("health")
def open_health_abuse_events_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.1] Open Abuse Events from AWS Health should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            response = health.describe_events(filter={"services": ["ABUSE"],"eventStatusCodes": ["open"]})
            if response["events"]:
                # this is a failing check
                for event in response["events"]:
                    eventArn = str(event["arn"])
                    eventRegion = str(event["region"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": awsAccountId + eventArn + "/health-active-abuse-events-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": eventArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[Health.1] Open Abuse Events from AWS Health should be investigated",
                        "Description": "There is an Active AWS Health Abuse event in the Region "
                        + eventRegion
                        + " with an ARN of "
                        + eventArn
                        + ". AWS Health Abuse events can come from the AWS Trust & Safety Team or AWS Security Operations team based on AWS scans and external reports, such as reports of your resources being used to distribute malware, pornography, or DDOS attacks. All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                                "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsHealthEvent",
                                "Id": eventArn,
                                "Partition": awsPartition,
                                "Region": awsRegion
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-2",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC 7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
            else:
                # if there is not an active Event the only thing to do would be to index on an Account
                # which would break the feel of these findings and would not be able to be Archived
                # so we will not write a finding at all
                pass
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Health Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("health")
def open_health_risk_events_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.2] Open Risk Events from AWS Health should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            response = health.describe_events(filter={"services": ["RISK"],"eventStatusCodes": ["open"]})
            if response["events"]:
                # this is a failing check
                for event in response["events"]:
                    eventArn = str(event["arn"])
                    eventRegion = str(event["region"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": awsAccountId + eventArn + "/health-active-risk-events-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": eventArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[Health.2] Open Risk Events from AWS Health should be investigated",
                        "Description": "There is an Active AWS Health Risk event in the Region "
                        + eventRegion
                        + " with an ARN of "
                        + eventArn
                        + ". AWS Health Risk events can come from the AWS Security Operations team based on AWS scans and external reports, such as reports of your resources being used to distribute malware, or having publicly exposed credentials on a public website (GitHub). All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                                "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsHealthEvent",
                                "Id": eventArn,
                                "Partition": awsPartition,
                                "Region": awsRegion
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-2",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC 7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
            else:
                # if there is not an active Event the only thing to do would be to index on an Account
                # which would break the feel of these findings and would not be able to be Archived
                # so we will not write a finding at all
                pass
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Health Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')

@registry.register_check("health")
def open_health_security_events_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.3] Open Security Events from AWS Health should be investigated"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if awsRegion == 'us-east-1':
        try:
            response = health.describe_events(filter={"services": ["SECURITY"],"eventStatusCodes": ["open"]})
            if response["events"]:
                # this is a failing check
                for event in response["events"]:
                    eventArn = str(event["arn"])
                    eventRegion = str(event["region"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": awsAccountId + eventArn + "/health-active-security-events-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": eventArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[Health.3] Open Security Events from AWS Health should be investigated",
                        "Description": "There is an Active AWS Health Risk event in the Region "
                        + eventRegion
                        + " with an ARN of "
                        + eventArn
                        + ". AWS Health Risk events can come from the AWS Security Operations team or AWS Service teams due to security changes to specific accounts, services, or global changes. All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                                "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsHealthEvent",
                                "Id": eventArn,
                                "Partition": awsPartition,
                                "Region": awsRegion
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF DE.AE-2",
                                "NIST SP 800-53 AU-6",
                                "NIST SP 800-53 CA-7",
                                "NIST SP 800-53 IR-4",
                                "NIST SP 800-53 SI-4",
                                "AICPA TSC 7.2",
                                "ISO 27001:2013 A.12.4.1",
                                "ISO 27001:2013 A.16.1.1",
                                "ISO 27001:2013 A.16.1.4"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
            else:
                pass
                # if there is not an active Event the only thing to do would be to index on an Account
                # which would break the feel of these findings and would not be able to be Archived
                # so we will not write a finding at all
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('You are not subscribed to AWS Premium Support - cannot use the Health Auditor')
            else:
                print(error)
    else:
        print('AWS Health Global endpoint is located in us-east-1')