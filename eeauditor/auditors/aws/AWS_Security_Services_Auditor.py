'''
This file is part of ElectricEye.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''

import boto3
import uuid
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
accessanalyzer = boto3.client("accessanalyzer")
guardduty = boto3.client("guardduty")
detective = boto3.client("detective")
macie2 = boto3.client("macie2")
wafv2 = boto3.client("wafv2")

@registry.register_check("accessanalyzer")
def iam_access_analyzer_detector_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.1] Amazon IAM Access Analyzer should be enabled"""
    response = accessanalyzer.list_analyzers()
    iamAccessAnalyzerCheck = str(response["analyzers"])
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # unique ID
    generatorUuid = str(uuid.uuid4())
    if iamAccessAnalyzerCheck == "[]":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/security-services-iaa-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorUuid,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SecSvcs.1] Amazon IAM Access Analyzer should be enabled",
            "Description": "Amazon IAM Access Analyzer is not enabled im " 
            + awsRegion
            + ". Refer to the remediation instructions if this configuration is not intended",
            "Remediation": {
                "Recommendation": {
                    "Text": "If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.16.1.4",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/security-services-iaa-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorUuid,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SecSvcs.1] Amazon IAM Access Analyzer should be enabled",
            "Description": "Amazon IAM Access Analyzer is enabled in "
            + awsRegion
            + ". ",
            "Remediation": {
                "Recommendation": {
                    "Text": "If IAM Access Analyzer should be enabled refer to the Enabling Access Analyzer section of the AWS Identity and Access Management User Guide",
                    "Url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#access-analyzer-enabling",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": "aws",
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF DE.AE-2",
                    "NIST SP 800-53 AU-6",
                    "NIST SP 800-53 CA-7",
                    "NIST SP 800-53 IR-4",
                    "NIST SP 800-53 SI-4",
                    "AICPA TSC 7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding

@registry.register_check("guardduty")
def guard_duty_detector_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.2] Amazon GuardDuty should be enabled"""
    response = guardduty.list_detectors()
    guarddutyDetectorCheck = str(response["DetectorIds"])
    # ISO Time
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    # unique ID
    generatorUuid = str(uuid.uuid4())
    if guarddutyDetectorCheck == "[]":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/security-services-guardduty-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorUuid,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[SecSvcs.2] Amazon GuardDuty should be enabled",
            "Description": "Amazon GuardDuty is not enabled in " 
            + awsRegion
            + ". Refer to the remediation instructions if this configuration is not intended",
            "Remediation": {
                "Recommendation": {
                    "Text": "If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide",
                    "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": "aws",
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.16.1.4",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/security-services-guardduty-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorUuid,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SecSvcs.2] Amazon GuardDuty should be enabled",
            "Description": "Amazon GuardDuty is not enabled in " 
            + awsRegion
            + ". Refer to the remediation instructions if this configuration is not intended",
            "Remediation": {
                "Recommendation": {
                    "Text": "If GuardDuty should be enabled refer to the Setting Up GuardDuty section of the Amazon GuardDuty User Guide",
                    "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": "aws",
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF DE.AE-2",
                    "NIST SP 800-53 AU-6",
                    "NIST SP 800-53 CA-7",
                    "NIST SP 800-53 IR-4",
                    "NIST SP 800-53 SI-4",
                    "AICPA TSC 7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding

@registry.register_check("detective")
def detective_graph_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.3] Amazon Detective should be enabled"""
    try:
        response = detective.list_graphs(MaxResults=200)
        # ISO Time
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        # unique ID
        generatorUuid = str(uuid.uuid4())
        if str(response["GraphList"]) == "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-detective-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SecSvcs.3] Amazon Detective should be enabled",
                "Description": "Amazon Detective is not enabled in ."
                + awsRegion
                + ". Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If Detective should be enabled refer to the Setting up Amazon Detective section of the Amazon Detective Administration Guide",
                        "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
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
                        "ISO 27001:2013 A.16.1.4",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-detective-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SecSvcs.3] Amazon Detective should be enabled",
                "Description": "Amazon Detective is enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If Detective should be enabled refer to the Setting up Amazon Detective section of the Amazon Detective Administration Guide",
                        "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC 7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
    except Exception as e:
        print(e)

@registry.register_check("macie2")
def macie_in_use_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.4] Amazon Macie V2 should be enabled"""
    try:
        # ISO Time
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        # unique ID
        generatorUuid = str(uuid.uuid4())
        try:
            response = macie2.get_macie_session()
            status = response["status"]
            if status == "PAUSED":
                raise Exception
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-macie-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SecSvcs.4] Amazon Macie V2 should be enabled",
                "Description": "Amazon Macie V2 is enabled in "
                + awsRegion
                + " .",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If Detective should be enabled refer to the Setting up Amazon Detective section of the Amazon Detective Administration Guide",
                        "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC 7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-macie-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SecSvcs.4] Amazon Macie V2 should be enabled",
                "Description": "Amazon Macie V2 is not enabled in "
                + awsRegion
                + ". Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If Macie should be enabled refer to the Getting started with Amazon Macie section of the Amazon Macie User Guide",
                        "Url": "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
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
                        "ISO 27001:2013 A.16.1.4",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
    except Exception as e:
        print(e)

@registry.register_check("macie2")
def wafv2_regional_in_use_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.5] AWS WAFv2 Regional Web ACLs should be used"""
    try:
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        # unique ID
        generatorUuid = str(uuid.uuid4())
        # this is a failing check
        if str(wafv2.list_web_acls(Scope='REGIONAL')["WebACLs"]) == "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-wafv2-regional-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SecSvcs.5] AWS WAFv2 Regional Web ACLs should be used",
                "Description": "AWS WAFv2 is present in "
                + awsRegion
                + " .",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If WAFv2 should be enabled refer to the Getting started with AWS WAF section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + awsRegion + "/security-services-wafv2-regional-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SecSvcs.5] AWS WAFv2 Regional Web ACLs should be used",
                "Description": "AWS WAFv2 is present in "
                + awsRegion
                + " .",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If WAFv2 should be enabled refer to the Getting started with AWS WAF section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
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
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
    except Exception as e:
        print(e)

@registry.register_check("macie2")
def wafv2_global_in_use_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecSvcs.6] AWS WAFv2 Global (CloudFront) Web ACLs should be used"""
    if awsRegion == "us-east-1":
        try:
            # ISO Time
            iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            # unique ID
            generatorUuid = str(uuid.uuid4())
            # this is a failing check
            if str(wafv2.list_web_acls(Scope='CLOUDFRONT')["WebACLs"]) == "[]":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + awsRegion + "/security-services-wafv2-global-in-use-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[SecSvcs.6] AWS WAFv2 Global (CloudFront) Web ACLs should be used",
                    "Description": "AWS WAFv2 is present in "
                    + awsRegion
                    + " .",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If WAFv2 should be enabled refer to the Getting started with AWS WAF section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
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
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + awsRegion + "/security-services-wafv2-global-in-use-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[SecSvcs.6] AWS WAFv2 Global (CloudFront) Web ACLs should be used",
                    "Description": "AWS WAFv2 is present in "
                    + awsRegion
                    + " .",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If WAFv2 should be enabled refer to the Getting started with AWS WAF section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/detective/latest/adminguide/detective-setup.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
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
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except Exception as e:
            print(e)
    else:
        print('Global WAFv2 Web ACLs for CloudFront can only be checked in us-east-1')