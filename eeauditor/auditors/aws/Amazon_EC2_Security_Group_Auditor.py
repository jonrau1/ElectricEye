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

import json
import os
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# Filename of the SG Auditor config JSON file
dirPath = os.path.dirname(os.path.realpath(__file__))
configFile = f"{dirPath}/electriceye_secgroup_auditor_config.json"

# loop through security groups
def describe_security_groups(cache, session):
    ec2 = session.client("ec2")
    response = cache.get("describe_security_groups")
    if response:
        return response
    cache["describe_security_groups"] = ec2.describe_security_groups()
    return cache["describe_security_groups"]

@registry.register_check("ec2")
def security_group_all_open_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityGroup.1] Security groups should not allow unrestricted access to all ports and protocols"""
    response = describe_security_groups(cache, session)
    mySgs = response["SecurityGroups"]
    for secgroup in mySgs:
        sgName = str(secgroup["GroupName"])
        sgId = str(secgroup["GroupId"])
        sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
        for permissions in secgroup["IpPermissions"]:
            try:
                ipProtocol = str(permissions["IpProtocol"])
            except Exception as e:
                print(e)
            ipRanges = permissions["IpRanges"]
            for cidrs in ipRanges:
                cidrIpRange = str(cidrs["CidrIp"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if ipProtocol == "-1" and cidrIpRange == "0.0.0.0/0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": sgArn + "/" + ipProtocol + "/security-group-all-open-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": sgArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[SecurityGroup.1] Security groups should not allow unrestricted access to all ports and protocols",
                        "Description": "Security group "
                        + sgName
                        + " allows unrestricted access to all ports and protocols. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEc2SecurityGroup",
                                "Id": sgArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId,}
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                elif ipProtocol == "-1" and cidrIpRange != "0.0.0.0/0":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": sgArn + "/" + ipProtocol + "/security-group-all-open-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": sgArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[SecurityGroup.1] Security groups should not allow unrestricted access to all ports and protocols",
                        "Description": "Security group "
                        + sgName
                        + " does not allow unrestricted access to all ports and protocols. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEc2SecurityGroup",
                                "Id": sgArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId,}
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
                else:
                    continue

@registry.register_check("ec2")
def security_group_master_auditor_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """The Security Group Master Auditor check generates findings for every configuration file entry"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

    # Open the Configuration file and parse the information within the dynamically populate this auditor
    with open(configFile, 'r') as jsonfile:
        for x in json.load(jsonfile):
            toPortTarget = x["ToPort"]
            fromPortTarget = x["FromPort"]
            targetProtocol = x["Protocol"]
            checkTitle = x["CheckTitle"]
            checkId = x["CheckId"]
            checkDescription = x["CheckDescriptor"]

            print(f"Auditing all Security Groups for unrestricted {checkDescription} access")

            # Parse security groups from Cache
            response = describe_security_groups(cache, session)
            mySgs = response["SecurityGroups"]
            for secgroup in mySgs:
                sgName = str(secgroup["GroupName"])
                sgId = str(secgroup["GroupId"])
                sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
                for permissions in secgroup["IpPermissions"]:
                    # If there any exceptions this SG is likely associated with a SG Target or a Peering Connection
                    try:
                        fromPort = permissions["FromPort"]
                    except KeyError:
                        continue
                    try:
                        toPort = permissions["ToPort"]
                    except KeyError:
                        continue
                    try:
                        ipProtocol = str(permissions["IpProtocol"])
                    except KeyError:
                        continue

                    # Now Process the Ranges
                    ipRanges = permissions["IpRanges"]
                    for cidrs in ipRanges:
                        cidrIpRange = str(cidrs["CidrIp"])
                
                        if (
                            toPort == toPortTarget
                            and fromPort == fromPortTarget
                            and ipProtocol == targetProtocol
                            and cidrIpRange == "0.0.0.0/0"
                        ):
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": f"{sgArn}/{ipProtocol}/{checkId}",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": sgArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure",
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "HIGH"},
                                "Confidence": 99,
                                "Title": checkTitle,
                                "Description": f"{sgName} allows unrestricted {checkDescription} access. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsEc2SecurityGroup",
                                        "Id": sgArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsEc2SecurityGroup": {
                                                "GroupName": sgName,
                                                "GroupId": sgId
                                            }
                                        }
                                    }
                                ],
                                "Compliance": {
                                    "Status": "FAILED",
                                    "RelatedRequirements": [
                                        "NIST CSF V1.1 PR.AC-3",
                                        "NIST SP 800-53 Rev. 4 AC-1",
                                        "NIST SP 800-53 Rev. 4 AC-17",
                                        "NIST SP 800-53 Rev. 4 AC-19",
                                        "NIST SP 800-53 Rev. 4 AC-20",
                                        "NIST SP 800-53 Rev. 4 SC-15",
                                        "AICPA TSC CC6.6",
                                        "ISO 27001:2013 A.6.2.1",
                                        "ISO 27001:2013 A.6.2.2",
                                        "ISO 27001:2013 A.11.2.6",
                                        "ISO 27001:2013 A.13.1.1",
                                        "ISO 27001:2013 A.13.2.1"
                                    ]
                                },
                                "Workflow": {"Status": "NEW"},
                                "RecordState": "ACTIVE"
                            }
                            yield finding
                        elif (
                            toPort == toPortTarget
                            and fromPort == fromPortTarget
                            and ipProtocol == targetProtocol
                            and cidrIpRange != "0.0.0.0/0"
                        ):
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": f"{sgArn}/{ipProtocol}/{checkId}",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": sgArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure",
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "INFORMATIONAL"},
                                "Confidence": 99,
                                "Title": checkTitle,
                                "Description": f"{sgName} does not allow unrestricted {checkDescription} access.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                                    }
                                },
                                "ProductFields": {"Product Name": "ElectricEye"},
                                "Resources": [
                                    {
                                        "Type": "AwsEc2SecurityGroup",
                                        "Id": sgArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsEc2SecurityGroup": {
                                                "GroupName": sgName,
                                                "GroupId": sgId
                                            }
                                        }
                                    }
                                ],
                                "Compliance": {
                                    "Status": "PASSED",
                                    "RelatedRequirements": [
                                        "NIST CSF V1.1 PR.AC-3",
                                        "NIST SP 800-53 Rev. 4 AC-1",
                                        "NIST SP 800-53 Rev. 4 AC-17",
                                        "NIST SP 800-53 Rev. 4 AC-19",
                                        "NIST SP 800-53 Rev. 4 AC-20",
                                        "NIST SP 800-53 Rev. 4 SC-15",
                                        "AICPA TSC CC6.6",
                                        "ISO 27001:2013 A.6.2.1",
                                        "ISO 27001:2013 A.6.2.2",
                                        "ISO 27001:2013 A.11.2.6",
                                        "ISO 27001:2013 A.13.1.1",
                                        "ISO 27001:2013 A.13.2.1"
                                    ]
                                },
                                "Workflow": {"Status": "RESOLVED"},
                                "RecordState": "ARCHIVED"
                            }
                            yield finding
                        else:
                            continue