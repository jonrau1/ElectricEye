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

def describe_directories(cache, session):
    ds = session.client("ds")
    response = cache.get("describe_directories")
    if response:
        return response
    cache["describe_directories"] = ds.describe_directories()
    return cache["describe_directories"]

@registry.register_check("ds")
def directory_service_radius_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for directory in describe_directories(cache, session)["DirectoryDescriptions"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(directory,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        directoryId = str(directory["DirectoryId"])
        directoryArn = f"arn:{awsPartition}:ds:{awsRegion}:{awsAccountId}:directory/{directoryId}"
        directoryName = str(directory["Name"])
        directoryType = str(directory["Type"])
        if directoryType != "SimpleAD":
            try:
                # this is a passing check
                directory["RadiusSettings"]
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": directoryArn + "/directory-service-radius-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": directoryArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)",
                    "Description": "Directory "
                    + directoryName
                    + " has RADIUS enabled and likely supports MFA.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide",
                            "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS Directory Service",
                        "AssetComponent": "Directory"
                    },
                    "Resources": [
                        {
                            "Type": "AwsDirectoryServiceDirectory",
                            "Id": directoryArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"DirectoryName": directoryName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-6",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 IA-1",
                            "NIST SP 800-53 Rev. 4 IA-2",
                            "NIST SP 800-53 Rev. 4 IA-4",
                            "NIST SP 800-53 Rev. 4 IA-5",
                            "NIST SP 800-53 Rev. 4 IA-8",
                            "NIST SP 800-53 Rev. 4 PE-2",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except KeyError:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": directoryArn + "/directory-service-radius-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": directoryArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[DirectoryService.1] Supported directories should have RADIUS enabled for multi-factor authentication (MFA)",
                    "Description": "Directory "
                    + directoryName
                    + " does not have RADIUS enabled and thus does not support MFA. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on directory MFA and configuring RADIUS refer to the Multi-factor Authentication Prerequisites section of the AWS Directory Service Administration Guide",
                            "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started_prereqs.html#prereq_mfa_ad",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Identity & Access Management",
                        "AssetService": "AWS Directory Service",
                        "AssetComponent": "Directory"
                    },
                    "Resources": [
                        {
                            "Type": "AwsDirectoryServiceDirectory",
                            "Id": directoryArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"DirectoryName": directoryName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-6",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 IA-1",
                            "NIST SP 800-53 Rev. 4 IA-2",
                            "NIST SP 800-53 Rev. 4 IA-4",
                            "NIST SP 800-53 Rev. 4 IA-5",
                            "NIST SP 800-53 Rev. 4 IA-8",
                            "NIST SP 800-53 Rev. 4 PE-2",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
        else:
            print(f"[DirectoryService.1] Check does not support {directoryId} as it is a SimpleAD directory type")
            continue

@registry.register_check("ds")
def directory_service_cloudwatch_logs_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DirectoryService.2] Directories should have log forwarding enabled"""
    ds = session.client("ds")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for directory in describe_directories(cache, session)["DirectoryDescriptions"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(directory,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        directoryId = str(directory["DirectoryId"])
        directoryArn = f"arn:{awsPartition}:ds:{awsRegion}:{awsAccountId}:directory/{directoryId}"
        directoryName = str(directory["Name"])
        if not ds.list_log_subscriptions(DirectoryId=directoryId)["LogSubscriptions"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": directoryArn + "/directory-service-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": directoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[DirectoryService.2] Directories should have log forwarding enabled",
                "Description": "Directory "
                + directoryName
                + " does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide",
                        "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS Directory Service",
                    "AssetComponent": "Directory"
                },
                "Resources": [
                    {
                        "Type": "AwsDirectoryServiceDirectory",
                        "Id": directoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"DirectoryName": directoryName}},
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
                "Id": directoryArn + "/directory-service-cloudwatch-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": directoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[DirectoryService.2] Directories should have log forwarding enabled",
                "Description": "Directory "
                + directoryName
                + " does not have log forwarding enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on directory log forwarding to CloudWatch Logs refer to the Enable Log Forwarding section of the AWS Directory Service Administration Guide",
                        "Url": "https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_log_forwarding.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "AWS Directory Service",
                    "AssetComponent": "Directory"
                },
                "Resources": [
                    {
                        "Type": "AwsDirectoryServiceDirectory",
                        "Id": directoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"DirectoryName": directoryName}},
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