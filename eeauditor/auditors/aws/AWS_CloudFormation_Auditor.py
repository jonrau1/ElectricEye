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
cloudformation = boto3.client("cloudformation")
# describe all cfn stacks
def describe_stacks(cache):
    response = cache.get("describe_stacks")
    if response:
        return response
    cache["describe_stacks"] = cloudformation.describe_stacks()
    return cache["describe_stacks"]

@registry.register_check("cloudformation")
def cfn_drift_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFormation.1] CloudFormation stacks should be monitored for configuration drift"""
    stack = describe_stacks(cache=cache)
    myCfnStacks = stack["Stacks"]
    for stacks in myCfnStacks:
        stackName = str(stacks["StackName"])
        stackId = str(stacks["StackId"])
        stackArn = f"arn:{awsPartition}:cloudformation:{awsRegion}:{awsAccountId}:stack/{stackName}/{stackId}"
        driftCheck = str(stacks["DriftInformation"]["StackDriftStatus"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if driftCheck != "IN_SYNC":
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
                "Description": "CloudFormation stack "
                + stackName
                + " has not been monitored for drift detection. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about drift detection refer to the Detecting Unmanaged Configuration Changes to Stacks and Resources section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"stackName": stackName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
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
                "Description": "CloudFormation stack "
                + stackName
                + " has been monitored for drift detection.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about drift detection refer to the Detecting Unmanaged Configuration Changes to Stacks and Resources section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"stackName": stackName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.MA-1",
                        "NIST SP 800-53 MA-2",
                        "NIST SP 800-53 MA-3",
                        "NIST SP 800-53 MA-5",
                        "NIST SP 800-53 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("cloudformation")
def cfn_monitoring_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFormation.2] CloudFormation stacks should be monitored for changes"""
    stack = describe_stacks(cache=cache)
    myCfnStacks = stack["Stacks"]
    for stacks in myCfnStacks:
        stackName = str(stacks["StackName"])
        stackId = str(stacks["StackId"])
        stackArn = f"arn:{awsPartition}:cloudformation:{awsRegion}:{awsAccountId}:stack/{stackName}/{stackId}"
        alertsCheck = str(stacks["NotificationARNs"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if alertsCheck == "[]":
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
                "Description": "CloudFormation stack "
                + stackName
                + " does not have monitoring enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your stack should having monitoring enabled refer to the Monitor and Roll Back Stack Operations section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"stackName": stackName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
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
                "Description": "CloudFormation stack " + stackName + " has monitoring enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your stack should having monitoring enabled refer to the Monitor and Roll Back Stack Operations section of the AWS CloudFormation User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-rollback-triggers.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudFormationStack",
                        "Id": stackArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"stackName": stackName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding