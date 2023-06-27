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
from botocore.exceptions import ClientError

registry = CheckRegister()

def global_region_generator(awsPartition):
    # Global Service Region override
    if awsPartition == "aws":
        globalRegion = "aws-global"
    elif awsPartition == "aws-us-gov":
        globalRegion = "aws-us-gov-global"
    elif awsPartition == "aws-cn":
        globalRegion = "aws-cn-global"
    elif awsPartition == "aws-iso":
        globalRegion = "aws-iso-global"
    elif awsPartition == "aws-isob":
        globalRegion = "aws-iso-b-global"
    elif awsPartition == "aws-isoe":
        globalRegion = "aws-iso-e-global"
    else:
        globalRegion = "aws-global"

    return globalRegion

def get_all_health_events(session, cache):
    response = cache.get("get_all_health_events")
    if response:
        return response
    
    try:
        health = session.client("health", region_name="us-east-1")

        cache["get_all_health_events"] = health.describe_events()["events"]
        return cache["get_all_health_events"]
    except ClientError:
        print("Not subscribed to AWS Premium Support!")
        return []

@registry.register_check("health")
def aws_health_open_abuse_events_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.1] AWS Health Abuse events that are not closed should be investigated"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # use a list comprehension to get matching events - instead of looping all of them, use the precense of one or not
    # to pass or fail the actual finding
    matchedEvents = [event for event in get_all_health_events(session, cache) if event["service"] == "ABUSE" and event["statusCode"] != "closed"]
    healthEventArn = f"arn:{awsPartition}:health::{awsAccountId}:event/ABUSE"
    # this is a failing finding
    if matchedEvents:
        assetJson = json.dumps(matchedEvents,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        matchedEventArns = [event["arn"] for event in matchedEvents]
        matchedArnSentence = ", ".join(matchedEventArns)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-abuse-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-abuse-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[Health.1] AWS Health Abuse events that are not closed should be investigated",
            "Description": f"AWS Health is reporting at least one open Abuse event for AWS Account {awsAccountId}. The following Health Event ARNs are open: {matchedArnSentence}. AWS Health Abuse events can come from the AWS Trust & Safety Team or AWS Security Operations team based on AWS scans and external reports, such as reports of your resources being used to distribute malware, pornography, or DDOS attacks. All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
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
        assetB64 = None
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-abuse-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-abuse-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Health.1] AWS Health Abuse events that are not closed should be investigated",
            "Description": f"AWS Health is not reporting any open Abuse event for AWS Account {awsAccountId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("health")
def aws_health_open_risk_events_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.2] AWS Health Risk events that are not closed should be investigated"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # use a list comprehension to get matching events - instead of looping all of them, use the precense of one or not
    # to pass or fail the actual finding
    matchedEvents = [event for event in get_all_health_events(session, cache) if event["service"] == "RISK" and event["statusCode"] != "closed"]
    healthEventArn = f"arn:{awsPartition}:health::{awsAccountId}:event/RISK"
    # this is a failing finding
    if matchedEvents:
        assetJson = json.dumps(matchedEvents,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        matchedEventArns = [event["arn"] for event in matchedEvents]
        matchedArnSentence = ", ".join(matchedEventArns)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-risk-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-risk-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[Health.2] AWS Health Risk events that are not closed should be investigated",
            "Description": f"AWS Health is reporting at least one open Risk event for AWS Account {awsAccountId}. The following Health Event ARNs are open: {matchedArnSentence}. AWS Health Risk events can come from the AWS Trust & Safety Team or AWS Security Operations team based on AWS scans and external reports, such as reports of your resources being used to distribute malware, pornography, or DDOS attacks. All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
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
        assetB64 = None
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-risk-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-risk-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Health.2] AWS Health Risk events that are not closed should be investigated",
            "Description": f"AWS Health is not reporting any open Risk event for AWS Account {awsAccountId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("health")
def aws_health_open_security_events_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Health.3] Open Security Events from AWS Health should be investigated"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # use a list comprehension to get matching events - instead of looping all of them, use the precense of one or not
    # to pass or fail the actual finding
    matchedEvents = [event for event in get_all_health_events(session, cache) if event["service"] == "SECURITY" and event["statusCode"] != "closed"]
    healthEventArn = f"arn:{awsPartition}:health::{awsAccountId}:event/SECURITY"
    # this is a failing finding
    if matchedEvents:
        assetJson = json.dumps(matchedEvents,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        matchedEventArns = [event["arn"] for event in matchedEvents]
        matchedArnSentence = ", ".join(matchedEventArns)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-security-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-security-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "CRITICAL"},
            "Confidence": 99,
            "Title": "[Health.2] AWS Health Security events that are not closed should be investigated",
            "Description": f"AWS Health is reporting at least one open Security event for AWS Account {awsAccountId}. The following Health Event ARNs are open: {matchedArnSentence}. AWS Health Security events can come from the AWS Trust & Safety Team or AWS Security Operations team based on AWS scans and external reports, such as reports of your resources being used to distribute malware, pornography, or DDOS attacks. All Active events should be investigated, refer to the remediation section for more information on using the Health service.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
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
        assetB64 = None
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{healthEventArn}/aws-health-active-security-events-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{healthEventArn}/aws-health-active-security-events-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Health.2] AWS Health Security events that are not closed should be investigated",
            "Description": f"AWS Health is not reporting any open Security event for AWS Account {awsAccountId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about viewing and working with Health Events refer to the Getting started with the AWS Personal Health Dashboard section of the AWS Health User Guide.",
                    "Url": "https://docs.aws.amazon.com/health/latest/ug/getting-started-phd.html#event-log"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "AWS Health",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "AwsHealthEvent",
                    "Id": healthEventArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

# END ??