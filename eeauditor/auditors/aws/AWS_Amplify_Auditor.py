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

registry = CheckRegister()

def list_apps(cache, session):
    amplify = session.client("amplify")
    response = cache.get("list_apps")
    if response:
        return response
    cache["list_apps"] = amplify.list_apps()
    return cache["list_apps"]

@registry.register_check("amplify")
def amplify_basic_auth_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Amplify.1] AWS Amplify should have basic auth enabled for branches"""
    response = list_apps(cache, session)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for apps in response["apps"]:
        appArn = apps['appArn']
        appName = apps['name']

        if str(apps['enableBasicAuth']) == 'True':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/amplify-basic-auth-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Amplify.1] AWS Amplify should have basic auth enabled for branches",
                "Description": "Amplify application "
                + appName
                + " has basic auth enabled for branches.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amplify branches should use basic auth to further protect branches from unauthorized access.  See the Amplify docs for more details",
                        "Url": "https://docs.aws.amazon.com/amplify/latest/userguide/access-control.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAmplifyApp",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"name": appName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.5",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        
        else: 
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/amplify-basic-auth-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Amplify.1] AWS Amplify should have basic auth enabled for branches",
                "Description": "Amplify application "
                + appName
                + " does not have basic auth enabled for branches.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amplify branches should use basic auth to further protect branches from unauthorized access.  See the Amplify docs for more details",
                        "Url": "https://docs.aws.amazon.com/amplify/latest/userguide/access-control.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAmplifyApp",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"name": appName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.5",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("amplify")
def amplify_branch_auto_deletion_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Amplify.2] AWS Amplify apps should have auto-deletion disabled for branches"""
    response = list_apps(cache, session)
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    for apps in response["apps"]:
        appArn = apps['appArn']
        appName = apps['name']

        if str(apps['enableBranchAutoDeletion']) == 'False':
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/amplify-branch-auto-deletion-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Amplify.2] AWS Amplify apps should have auto-deletion disabled for branches",
                "Description": "Amplify application "
                + appName
                + " does not have auto-deletion enabled on branches.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amplify branches should not allow auto-deletion.  See the Amplify docs for more details",
                        "Url": "https://docs.aws.amazon.com/amplify/latest/userguide/welcome.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAmplifyApp",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"name": appName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.5",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        
        else: 
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": appArn + "/amplify-branch-auto-deletion-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Amplify.2] AWS Amplify apps should have auto-deletion disabled for branches",
                "Description": "Amplify application "
                + appName
                + " has auto-deletion enabled on branches.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amplify branches should not allow auto-deletion.  See the Amplify docs for more details",
                        "Url": "https://docs.aws.amazon.com/amplify/latest/userguide/welcome.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAmplifyApp",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"name": appName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.5",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding