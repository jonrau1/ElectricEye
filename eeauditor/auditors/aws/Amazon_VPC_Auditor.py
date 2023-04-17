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

def describe_vpcs(cache, session):
    ec2 = session.client("ec2")
    response = cache.get("describe_vpcs")
    if response:
        return response
    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)
    return cache["describe_vpcs"]

@registry.register_check("ec2")
def vpc_default_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.1] Consider deleting the Default VPC if unused"""
    vpc = describe_vpcs(cache, session)
    for vpcs in vpc["Vpcs"]:
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
                + " has been identified as the Default VPC, consider deleting this VPC if it is not necessary for daily operations. The Default VPC in AWS Regions not typically used can serve as a persistence area for malicious actors, additionally, many services will automatically use this VPC which can lead to a degraded security posture. Refer to the remediation instructions if this configuration is not intended",
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
                        "Details": {"Other": {"VpcId": vpcId}},
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
                        "Details": {"Other": {"VpcId": vpcId}},
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
def vpc_flow_logs_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.2] Flow Logs should be enabled for all VPCs"""
    ec2 = session.client("ec2")
    vpc = describe_vpcs(cache, session)
    for vpcs in vpc["Vpcs"]:
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
                        "Details": {"Other": {"VpcId": vpcId}},
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
                        "Details": {"Other": {"VpcId": vpcId}},
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

@registry.register_check("ec2")
def subnet_public_ip_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.3] Subnets should not automatically map Public IP addresses on launch"""
    ec2 = session.client("ec2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    vpc = describe_vpcs(cache, session)
    myVpcs = vpc["Vpcs"]
    for vpcs in myVpcs:
        vpcId = str(vpcs["VpcId"])
        # Get subnets for the VPC
        for snet in ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values': [vpcId]}])["Subnets"]:
            snetArn = str(snet["SubnetArn"])
            snetId = str(snet["SubnetId"])
        
            if str(snet["MapPublicIpOnLaunch"]) == "True":
                # This is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": snetArn + "/subnet-map-public-ip-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": snetArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[VPC.3] Subnets should not automatically map Public IP addresses on launch",
                    "Description": "Subnet "
                    + snetId
                    + " maps Public IPs on Launch, consider disabling this to avoid unncessarily exposing workloads to the internet. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Subnet",
                            "Id": snetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "VpcId": vpcId,
                                    "SubnetId": snetId
                                }
                            }
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
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": snetArn + "/subnet-map-public-ip-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": snetArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[VPC.3] Subnets should not automatically map Public IP addresses on launch",
                    "Description": "Subnet "
                    + snetId
                    + " does not map Public IPs on Launch.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Subnet",
                            "Id": snetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "VpcId": vpcId,
                                    "SubnetId": snetId
                                }
                            }
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
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("ec2")
def subnet_no_ip_space_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.4] Subnets should be monitored for available IP address space"""
    ec2 = session.client("ec2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    vpc = describe_vpcs(cache, session)
    myVpcs = vpc["Vpcs"]
    for vpcs in myVpcs:
        vpcId = str(vpcs["VpcId"])
        # Get subnets for the VPC
        for snet in ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values': [vpcId]}])["Subnets"]:
            snetArn = str(snet["SubnetArn"])
            snetId = str(snet["SubnetId"])
        
            if int(snet["AvailableIpAddressCount"]) <= 1:
                # This is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": snetArn + "/subnet-map-no-more-ips-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": snetArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[VPC.4] Subnets should be monitored for available IP address space",
                    "Description": "Subnet "
                    + snetId
                    + " does not have any available IP address space, consider terminating unncessary workloads or expanding CIDR capacity to avoid availability losses. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Subnet",
                            "Id": snetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "VpcId": vpcId,
                                    "SubnetId": snetId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": snetArn + "/subnet-map-no-more-ips-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": snetArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[VPC.4] Subnets should be monitored for available IP address space",
                    "Description": "Subnet "
                    + snetId
                    + " has available IP address space, well, at least 2 lol...",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Subnet",
                            "Id": snetArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "VpcId": vpcId,
                                    "SubnetId": snetId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding