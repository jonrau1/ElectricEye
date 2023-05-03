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

def describe_stacks(cache, session):
    cloudformation = session.client("cloudformation")
    response = cache.get("describe_stacks")
    if response:
        return response
    cache["describe_stacks"] = cloudformation.describe_stacks()
    return cache["describe_stacks"]

@registry.register_check("cloudformation")
def cfn_drift_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFormation.1] CloudFormation stacks should be monitored for configuration drift"""
    for stacks in describe_stacks(cache, session)["Stacks"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(stacks,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        stackName = str(stacks["StackName"])
        stackArn = str(stacks["StackId"])
        driftCheck = str(stacks["DriftInformation"]["StackDriftStatus"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if driftCheck != "IN_SYNC":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": stackArn + "/cloudformation-drift-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": stackArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudFormation.1] CloudFormation stacks should be monitored for configuration drift",
                "Description": f"CloudFormation stack {stackName} is either not in-sync with drift or is not monitored for drift. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about drift detection refer to the Detecting Unmanaged Configuration Changes to Stacks and Resources section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS CloudFormation",
                    "AssetComponent": "Stack"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StackName": stackName}},
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": stackArn + "/cloudformation-drift-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": stackArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFormation.1] CloudFormation stacks should be monitored for configuration drift",
                "Description": f"CloudFormation stack {stackName} is being monitored for drift and is in sync.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about drift detection refer to the Detecting Unmanaged Configuration Changes to Stacks and Resources section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS CloudFormation",
                    "AssetComponent": "Stack"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StackName": stackName}},
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

@registry.register_check("cloudformation")
def cfn_monitoring_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFormation.2] CloudFormation stacks should be monitored for changes"""
    for stacks in describe_stacks(cache, session)["Stacks"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(stacks,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        stackName = str(stacks["StackName"])
        stackArn = str(stacks["StackId"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if not stacks["NotificationARNs"]:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": stackArn + "/cloudformation-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": stackArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudFormation.2] CloudFormation stacks should be monitored for changes",
                "Description": f"CloudFormation stack {stackName} does not have monitoring enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your stack should having monitoring enabled refer to the Monitor and Roll Back Stack Operations section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS CloudFormation",
                    "AssetComponent": "Stack"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StackName": stackName}},
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": stackArn + "/cloudformation-monitoring-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": stackArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFormation.2] CloudFormation stacks should be monitored for changes",
                "Description": f"CloudFormation stack {stackName} has monitoring enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your stack should having monitoring enabled refer to the Monitor and Roll Back Stack Operations section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "AWS CloudFormation",
                    "AssetComponent": "Stack"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"StackName": stackName}},
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding