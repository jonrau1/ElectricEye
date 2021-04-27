# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
amplify = boto3.client("amplify")


def list_apps(cache):
    response = cache.get("list_apps")
    if response:
        return response
    cache["list_apps"] = amplify.list_apps()
    return cache["list_apps"]


@registry.register_check("amplify")
def amplify_basic_auth_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_apps(cache)
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
                        "NIST CSF PR.DS-1",
                        "NIST CSF PR.DS-5",
                        "NIST CSF PR.IP-3",
                        "NIST SP 800-53 AC-6",
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
                        "NIST CSF PR.DS-1",
                        "NIST CSF PR.DS-5",
                        "NIST CSF PR.IP-3",
                        "NIST SP 800-53 AC-6",
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
def amplify_branch_auto_deletion_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = list_apps(cache)
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
                        "NIST CSF PR.DS-1",
                        "NIST CSF PR.DS-5",
                        "NIST CSF PR.IP-3",
                        "NIST SP 800-53 AC-6",
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
                        "NIST CSF PR.DS-1",
                        "NIST CSF PR.DS-5",
                        "NIST CSF PR.IP-3",
                        "NIST SP 800-53 AC-6",
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