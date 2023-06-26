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
from botocore.exceptions import ClientError
import datetime
import base64
import json

registry = CheckRegister()

def get_guardduty_detectors(cache, session):
    response = cache.get("get_guardduty_detectors")
    if response:
        return response
    
    guardduty = session.client("guardduty")
    guarddutyDetectors = []

    try:
        for detector in guardduty.list_detectors()["DetectorIds"]:
            detectorDetail = guardduty.get_detector(DetectorId=detector)
            detectorDetail["DetectorId"] = detector
            guarddutyDetectors.append(
                detectorDetail
            )
        cache["get_guardduty_detectors"] = guarddutyDetectors
        return cache["get_guardduty_detectors"]
    except ClientError:
        cache["get_guardduty_detectors"] = []
        return cache["get_guardduty_detectors"]
    
@registry.register_check("guardduty")
def amazon_guardduty_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.1] Amazon GuardDuty should be enabled in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    detectorData = get_guardduty_detectors(cache, session)
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(detectorData,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if not detectorData:
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
            "Title": "[GuardDuty.1] Amazon GuardDuty should be enabled in the current AWS Region",
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
                "AssetDetails": None,
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
            "Title": "[GuardDuty.1] Amazon GuardDuty should be enabled in the current AWS Region",
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

@registry.register_check("guardduty")
def amazon_guardduty_s3_protection_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.2] Amazon GuardDuty detectors should enable S3 Protection in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "S3_DATA_EVENTS"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-s3-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-s3-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.2] Amazon GuardDuty detectors should enable S3 Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have S3 Protection enabled or does not have a detector enabled. S3 protection enables Amazon GuardDuty to monitor object-level API operations to identify potential security risks for data within your S3 buckets. GuardDuty monitors threats against your Amazon S3 resources by analyzing AWS CloudTrail management events and CloudTrail S3 data events. These data sources monitor different kinds of activity, for example, CloudTrail management events for S3 include operations that list or configure S3 buckets, such as ListBuckets, DeleteBuckets, and PutBucketReplication. Examples of data events for S3 include object-level API operations, such as GetObject, ListObjects, DeleteObject, and PutObject. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of S3 Protection refer to the Amazon S3 Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html"
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
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
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
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-s3-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-s3-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.2] Amazon GuardDuty detectors should enable S3 Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have S3 Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of S3 Protection refer to the Amazon S3 Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/s3-protection.html"
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
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
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
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("guardduty")
def amazon_guardduty_eks_audit_log_monitoring_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.3] Amazon GuardDuty detectors should enable EKS Audit Log Monitoring in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "EKS_AUDIT_LOGS"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-eks-audit-log-monitoring-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-eks-audit-log-monitoring-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.3] Amazon GuardDuty detectors should enable EKS Audit Log Monitoring in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have EKS Audit Log Monitoring enabled or does not have a detector enabled. EKS Audit Log Monitoring helps you detect potentially suspicious activities in your EKS clusters within Amazon Elastic Kubernetes Service. When you enable EKS Audit Log Monitoring, GuardDuty immediately begins to monitor Kubernetes audit logs from your Amazon EKS clusters and analyze them for potentially malicious and suspicious activity. It consumes Kubernetes audit log events directly from the Amazon EKS control plane logging feature through an independent and duplicative stream of flow logs. This process does not require any additional set up or affect any existing Amazon EKS control plane logging configurations that you might have. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EKS Audit Log Monitoring refer to the EKS Audit Log Monitoring section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-eks-audit-log-monitoring.html"
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
                "Id": f"{guarddutyAccountArn}/guardduty-eks-audit-log-monitoring-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-eks-audit-log-monitoring-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.3] Amazon GuardDuty detectors should enable EKS Audit Log Monitoring in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have EKS Audit Log Monitoring enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EKS Audit Log Monitoring refer to the EKS Audit Log Monitoring section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-eks-audit-log-monitoring.html"
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

@registry.register_check("guardduty")
def amazon_guardduty_eks_runtime_monitoring_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.4] Amazon GuardDuty detectors should enable EKS Runtime Monitoring in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "EKS_RUNTIME_MONITORING"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-eks-runtime-monitoring-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-eks-runtime-monitoring-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.4] Amazon GuardDuty detectors should enable EKS Runtime Monitoring in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have EKS Runtime Monitoring enabled or does not have a detector enabled. EKS Runtime Monitoring provides runtime threat detection coverage for Amazon Elastic Kubernetes Service (Amazon EKS) nodes and containers within your AWS environment. EKS Runtime Monitoring uses a new GuardDuty security agent (EKS add-on) that adds runtime visibility into individual EKS workloads, for example, file access, process execution, and network connections. The GuardDuty security agent helps GuardDuty identify specific containers within your EKS clusters that are potentially compromised. It can also detect attempts to escalate privileges from an individual container to the underlying EC2 host, and the broader AWS environment. For more information, see Runtime Monitoring. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EKS Runtime Monitoring refer to the EKS Runtime Monitoring section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-eks-runtime-monitoring.html"
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
                "Id": f"{guarddutyAccountArn}/guardduty-eks-runtime-monitoring-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-eks-runtime-monitoring-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.4] Amazon GuardDuty detectors should enable EKS Runtime Monitoring in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have EKS Runtime Monitoring enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EKS Runtime Monitoring refer to the EKS Runtime Monitoring section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-eks-runtime-monitoring.html"
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

@registry.register_check("guardduty")
def amazon_guardduty_rds_protection_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.5] Amazon GuardDuty detectors should enable RDS Protection in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "RDS_LOGIN_EVENTS"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-rds-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-rds-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.5] Amazon GuardDuty detectors should enable RDS Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have RDS Protection enabled or does not have a detector enabled. RDS Protection in Amazon GuardDuty analyzes and profiles RDS login activity for potential access threats to your Amazon Aurora databases (Amazon Aurora MySQL-Compatible Edition and Aurora PostgreSQL-Compatible Edition). This feature allows you to identify potentially suspicious login behavior. RDS Protection doesn't require additional infrastructure; it is designed so as not to affect the performance of your database instances. When RDS Protection detects a potentially suspicious or anomalous login attempt that indicates a threat to your database, GuardDuty generates a new finding with details about the potentially compromised database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of RDS Protection refer to the GuardDuty RDS Protection section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/rds-protection.html"
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
                "Id": f"{guarddutyAccountArn}/guardduty-rds-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-rds-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.5] Amazon GuardDuty detectors should enable RDS Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have RDS Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of RDS Protection refer to the GuardDuty RDS Protection section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/rds-protection.html"
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

@registry.register_check("guardduty")
def amazon_guardduty_ec2_malware_protection_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.6] Amazon GuardDuty detectors should enable Amazon EC2/EBS Malware Protection in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "EBS_MALWARE_PROTECTION"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-ec2-malware-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-ec2-malware-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.6] Amazon GuardDuty detectors should enable Amazon EC2/EBS Malware Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have Amazon EC2/EBS Malware Protection enabled or does not have a detector enabled. Malware Protection helps you detect the potential presence of malware by scanning the Amazon Elastic Block Store (Amazon EBS) volumes that are attached to the Amazon Elastic Compute Cloud (Amazon EC2) instances and container workloads. Malware Protection provides scan options where you can decide if you want to include or exclude specific Amazon EC2 instances and container workloads at the time of scanning. It also provides an option to retain the snapshots of Amazon EBS volumes attached to the Amazon EC2 instances or container workloads, in your GuardDuty accounts. The snapshots get retained only when malware is found and Malware Protection findings are generated. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EC2/EBS Malware Protection refer to the Malware Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection.html"
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
                "Id": f"{guarddutyAccountArn}/guardduty-ec2-malware-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-ec2-malware-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.6] Amazon GuardDuty detectors should enable Amazon EC2/EBS Malware Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have Amazon EC2/EBS Malware Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of EC2/EBS Malware Protection refer to the Malware Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/malware-protection.html"
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

@registry.register_check("guardduty")
def amazon_guardduty_lambda_protection_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GuardDuty.7] Amazon GuardDuty detectors should enable AWS Lambda Protection in the current AWS Region"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # GuardDuty "account level" ARN
    guarddutyAccountArn = f"arn:{awsPartition}:guardduty:{awsRegion}:{awsAccountId}:detector"
    for detector in get_guardduty_detectors(cache, session):
        # B64 encode all of the details for the Asset
        if detector:
            assetJson = json.dumps(detector,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Use list comprehensions to check if the Detector is enabled and if the specific Protection Plan is configured
            protectionPlan = [feature for feature in detector["Features"] if feature["Name"] == "LAMBDA_NETWORK_LOGS"][0]
            if protectionPlan["Status"] == "ENABLED":
                protectionPlanEnabled = True
            else:
                protectionPlanEnabled = False
        else:
            protectionPlanEnabled = False
            assetB64 = None
        # this is a failing check
        if protectionPlanEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{guarddutyAccountArn}/guardduty-aws-lambda-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-aws-lambda-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GuardDuty.7] Amazon GuardDuty detectors should enable AWS Lambda Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does not have AWS Lambda Protection enabled or does not have a detector enabled. Lambda Protection helps you identify potential security threats when an AWS Lambda function gets invoked in your AWS environment. When you enable Lambda Protection, GuardDuty starts monitoring Lambda network activity logs, starting with VPC Flow Logs from all Lambda functions for account, including those logs that don't use VPC networking, and are generated when the Lambda function gets invoked. If GuardDuty identifies suspicious network traffic that is indicative of the presence of a potentially malicious piece of code in your Lambda function, GuardDuty will generate a finding. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of AWS Lambda Protection refer to the Lambda Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html"
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
                "Id": f"{guarddutyAccountArn}/guardduty-aws-lambda-protection-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{guarddutyAccountArn}/guardduty-aws-lambda-protection-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GuardDuty.7] Amazon GuardDuty detectors should enable AWS Lambda Protection in the current AWS Region",
                "Description": f"Amazon GuardDuty detector in AWS Region {awsRegion} for AWS Account {awsAccountId} does have AWS Lambda Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the purpose and configuration of AWS Lambda Protection refer to the Lambda Protection in Amazon GuardDuty section of the Amazon GuardDuty User Guide",
                        "Url": "https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html"
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

## END ??