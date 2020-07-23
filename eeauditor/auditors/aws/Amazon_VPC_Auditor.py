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
# create boto3 clients
ec2 = boto3.client("ec2")
# loop through vpcs
def describe_vpcs(cache):
    response = cache.get("describe_vpcs")
    if response:
        return response
    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)
    return cache["describe_vpcs"]


@registry.register_check("ec2")
def vpc_default_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    vpc = describe_vpcs(cache=cache)
    myVpcs = vpc["Vpcs"]
    for vpcs in myVpcs:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        defaultVpcCheck = str(vpcs["IsDefault"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if defaultVpcCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/vpc-is-default-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.1] Consider deleting the Default VPC if unused",
                "Description": "VPC "
                + vpcId
                + " has been identified as the Default VPC, consider deleting this VPC if it is not necessary for daily operations. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"vpcId": vpcId}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/vpc-is-default-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.1] Consider deleting the Default VPC if unused",
                "Description": "VPC " + vpcId + " is not the Default VPC",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"vpcId": vpcId}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("ec2")
def vpc_flow_logs_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    vpc = describe_vpcs(cache=cache)
    myVpcs = vpc["Vpcs"]
    for vpcs in myVpcs:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        response = ec2.describe_flow_logs(
            DryRun=False, Filters=[{"Name": "resource-id", "Values": [vpcId]}]
        )
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if str(response["FlowLogs"]) == "[]":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/vpc-flow-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.2] Flow Logs should be enabled for all VPCs",
                "Description": "VPC "
                + vpcId
                + " does not have flow logging enabled. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"vpcId": vpcId}},
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
                "Id": vpcArn + "/vpc-flow-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.2] Flow Logs should be enabled for all VPCs",
                "Description": "VPC " + vpcId + " has flow logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"vpcId": vpcId}},
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

