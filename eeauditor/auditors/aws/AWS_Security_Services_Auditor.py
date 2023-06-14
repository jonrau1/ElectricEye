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
import base64
import json

registry = CheckRegister()

@registry.register_check("guardduty")
def guard_duty_detector_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.1] Amazon GuardDuty should be enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    
    guardduty = session.client("guardduty")
    r = guardduty.list_detectors()
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(r,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if not r["DetectorIds"]:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{guarddutyAccountArn}/guardduty-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{guarddutyAccountArn}/guardduty-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[GuardDuty.1] Amazon GuardDuty should be enabled",
            "Description": f"Amazon GuardDuty is not enabled in {awsRegion}. AWS GuardDuty is a threat detection service that continuously monitors your AWS accounts and workloads for malicious activity and unauthorized behavior. By enabling GuardDuty, you can detect and respond to security threats faster and with more accuracy, reducing the risk of security breaches and data loss. GuardDuty uses machine learning and threat intelligence to analyze event data from multiple sources, including VPC Flow Logs, DNS logs, and AWS CloudTrail logs. It also provides actionable findings and prioritizes security alerts based on their severity, allowing you to focus on the most critical threats first. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide",
                    "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon GuardDuty",
                "AssetComponent": "Account Activation"
            },
            "Resources": [
                {
                    "Type": "AwsGuardDutyDetector",
                    "Id": guarddutyAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{guarddutyAccountArn}/guardduty-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{guarddutyAccountArn}/guardduty-enabled-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[GuardDuty.1] Amazon GuardDuty should be enabled",
            "Description": f"Amazon GuardDuty is enabled in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide",
                    "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon GuardDuty",
                "AssetComponent": "Detector"
            },
            "Resources": [
                {
                    "Type": "AwsGuardDutyDetector",
                    "Id": guarddutyAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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

@registry.register_check("detective")
def detective_graph_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Detective.1] Amazon Detective should be enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Detective "account level" ARN
    detectiveAccountArn = f"arn:{awsPartition}:detective:{awsRegion}:{awsAccountId}:graph"
    
    detective = session.client("detective")
    r = detective.list_graphs(MaxResults=200)
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(r,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)   
    if not r["GraphList"]:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{detectiveAccountArn}/detective-activated-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{detectiveAccountArn}/detective-activated-check",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Detective.1] Amazon Detective should be enabled",
            "Description": f"Amazon Detective is not enabled in {awsRegion}. Amazon Detective is a fully managed security service that helps you investigate and identify the root cause of potential security issues or suspicious activities across your AWS environment. By using Amazon Detective, you can quickly and easily analyze log data from multiple sources, including VPC Flow Logs, AWS CloudTrail, and DNS logs, and visualize the relationships between resources and events, making it easier to understand and identify security incidents. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If Detective should be enabled refer to the Setting up Amazon Detective section of the Amazon Detective Administration Guide",
                    "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Detective",
                "AssetComponent": "Graph"
            },
            "Resources": [
                {
                    "Type": "AwsDetectiveGraph",
                    "Id": detectiveAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{detectiveAccountArn}/detective-activated-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{detectiveAccountArn}/detective-activated-check",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Detective.1] Amazon Detective should be enabled",
            "Description": f"Amazon Detective is enabled in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If Detective should be enabled refer to the Setting up Amazon Detective section of the Amazon Detective Administration Guide",
                    "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Detective",
                "AssetComponent": "Graph"
            },
            "Resources": [
                {
                    "Type": "AwsDetectiveGraph",
                    "Id": detectiveAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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

@registry.register_check("macie2")
def macie_in_use_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Macie.1] Amazon Macie V2 should be enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Macie2 "account level" ARN
    macieAccountArn = f"arn:{awsPartition}:macie2:{awsRegion}:{awsAccountId}"

    macie2 = session.client("macie2")
    try:
        r = macie2.get_macie_session()
        if r["status"] == "PAUSED":
            macieEnabled = False
        else:
            macieEnabled = True
        assetJson = json.dumps(r,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
    except Exception:
        macieEnabled = False
        assetB64 = None
    
    # This is a passing check
    if macieEnabled is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{macieAccountArn}/macie2-activated-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{macieAccountArn}/macie2-activated-check",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Macie.1] Amazon Macie V2 should be enabled",
            "Description": f"Amazon Macie V2 is enabled in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If Macie should be enabled refer to the Getting started with Amazon Macie section of the Amazon Macie User Guide",
                    "Url": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Macie",
                "AssetComponent": "Session"
            },
            "Resources": [
                {
                    "Type": "AwsMacie2Session",
                    "Id": macieAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{macieAccountArn}/macie2-activated-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{macieAccountArn}/macie2-activated-check",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Macie.1] Amazon Macie V2 should be enabled",
            "Description": f"Amazon Macie V2 is not enabled in {awsRegion}. This is either due to insufficient permissions to check, Macie2 not being activiated, or the Macie2 Session being paused or disabled. AWS Macie is a fully managed data security and privacy service that uses machine learning to automatically discover, classify, and protect sensitive data stored in AWS. By enabling Macie, you can improve your data security posture, comply with regulatory requirements, and prevent data breaches. Macie scans data stored in S3 buckets, analyzes access patterns, and provides detailed visibility and insights into your data, including identifying sensitive data such as personally identifiable information (PII) and intellectual property. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If Macie should be enabled refer to the Getting started with Amazon Macie section of the Amazon Macie User Guide",
                    "Url": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Macie",
                "AssetComponent": "Session"
            },
            "Resources": [
                {
                    "Type": "AwsMacie2Session",
                    "Id": macieAccountArn,
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.16.1.4",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.4"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding

## END FOR NOW...