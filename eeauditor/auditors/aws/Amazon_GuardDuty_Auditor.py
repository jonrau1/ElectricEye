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
def guard_duty_detector_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
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