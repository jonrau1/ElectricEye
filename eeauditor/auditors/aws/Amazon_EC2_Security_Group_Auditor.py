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
from os import path
import json
import base64
import datetime

registry = CheckRegister()

# Filename of the SG Auditor config JSON file
dirPath = path.dirname(path.realpath(__file__))
try:
    configFile = f"{dirPath}/electriceye_secgroup_auditor_config.json"
except Exception as e:
    raise e

# loop through security groups
def describe_security_groups(cache, session):
    response = cache.get("describe_security_groups")
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_security_groups"] = ec2.describe_security_groups()["SecurityGroups"]
    return cache["describe_security_groups"]

@registry.register_check("ec2")
def security_group_all_open_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityGroup.1] AWS EC2 security groups should not allow unrestricted access to all ports and protocols"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for secgroup in describe_security_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(secgroup,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        sgName = secgroup["GroupName"]
        sgId = secgroup["GroupId"]
        sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
        for permissions in secgroup["IpPermissions"]:
            try:
                ipProtocol = permissions["IpProtocol"]
            except KeyError:
                ipProtocol = None
            
            # Unfold both IPv4 and v6 - these will be present no matter what
            ipV4Ranges = permissions.get("IpRanges", [])
            ipV6Ranges = permissions.get("Ipv6Ranges", [])
            
            # By default, assume that the CIDR is NOT public (0.0.0.0/0 or ::/0) - then if there are entries for a subsequent
            # IPv4/6 Range AND there is an entry for the public CIDR - set the current rule to a failing state my making
            # "wholeInternetCidr" set to True
            wholeInternetCidr = False
            if (ipV4Ranges and any(ipV4Range.get("CidrIp") == "0.0.0.0/0" for ipV4Range in ipV4Ranges)) or \
            (ipV6Ranges and any(ipV6Range.get("CidrIpv6") == "::/0" for ipV6Range in ipV6Ranges)):
                wholeInternetCidr = True
            
            # This is a failing finding
            if ipProtocol == "-1" and wholeInternetCidr is True:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{sgArn}/{ipProtocol}/security-group-all-open-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{sgArn}/{ipProtocol}/security-group-all-open-check",
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
                    "Title": "[SecurityGroup.1] AWS EC2 security groups should not allow unrestricted access to all ports and protocols",
                    "Description": f"AWS EC2 Security group {sgName} contains a rule that allows unrestricted access to all ports and protocols. Security Groups are often the first line of defense for network boundaries in AWS, allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, ensure that Network Firewalls, Route 53 Resolver DNS Firewalls, WAFv2, or some other self-managed host- or network-based appliance exists to interdict and prevent adversarial network traffic from reaching your hosts.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon VPC",
                        "AssetComponent": "Security Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": sgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId}
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.2",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.3",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.2",
                            "CIS Amazon Web Services Foundations Benchmark V3.0 5.2",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.3",
                            "CIS Amazon Web Services Foundations Benchmark V3.0 5.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            elif ipProtocol == "-1" and wholeInternetCidr is False:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{sgArn}/{ipProtocol}/security-group-all-open-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{sgArn}/{ipProtocol}/security-group-all-open-check",
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
                    "Title": "[SecurityGroup.1] AWS EC2 security groups should not allow unrestricted access to all ports and protocols",
                    "Description": f"AWS EC2 security group {sgName} does not allow unrestricted access to all ports and protocols. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon VPC",
                        "AssetComponent": "Security Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": sgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId}
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.2",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                continue

@registry.register_check("ec2")
def security_group_master_auditor_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityGroup.{checkIdNumber}] AWS EC2 security groups should not allow unrestricted {protocol} access"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Open the Configuration file and parse the information within the dynamically populate this auditor
    with open(configFile, "r") as jsonfile:
        for x in json.load(jsonfile):
            toPortTarget = x["ToPort"]
            fromPortTarget = x["FromPort"]
            targetProtocol = x["Protocol"]
            checkTitle = x["CheckTitle"]
            checkId = x["CheckId"]
            checkDescription = x["CheckDescriptor"]

            for secgroup in describe_security_groups(cache, session):
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(secgroup,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                sgName = secgroup["GroupName"]
                sgId = secgroup["GroupId"]
                sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
                for permissions in secgroup["IpPermissions"]:
                    # If there any exceptions this SG is likely associated with a SG Target or a Peering Connection
                    if not all(key in permissions for key in ["FromPort", "ToPort", "IpProtocol"]):
                        continue
                    else:
                        toPort = permissions["ToPort"]
                        fromPort = permissions["FromPort"]
                        ipProtocol = permissions["IpProtocol"]
                    # Unfold both IPv4 and v6 - these will be present no matter what
                    ipV4Ranges = permissions.get("IpRanges", [])
                    ipV6Ranges = permissions.get("Ipv6Ranges", [])
                    # By default, assume that the CIDR is NOT public (0.0.0.0/0 or ::/0) - then if there are entries for a subsequent
                    # IPv4/6 Range AND there is an entry for the public CIDR - set the current rule to a failing state my making
                    # "wholeInternetCidr" set to True
                    wholeInternetCidr = False
                    if (ipV4Ranges and any(ipV4Range.get("CidrIp") == "0.0.0.0/0" for ipV4Range in ipV4Ranges)) or \
                    (ipV6Ranges and any(ipV6Range.get("CidrIpv6") == "::/0" for ipV6Range in ipV6Ranges)):
                        wholeInternetCidr = True

                    # This is a failing finding - it matches all ports, protocols and has an open CIDR
                    if (
                        toPort == toPortTarget
                        and fromPort == fromPortTarget
                        and ipProtocol == targetProtocol
                        and wholeInternetCidr is True
                    ):
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{sgArn}/{ipProtocol}/{checkId}",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": f"{sgArn}/{ipProtocol}/{checkId}",
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": checkTitle,
                            "Description": f"{sgName} allows unrestricted {checkDescription} access. Security Groups are often the first line of defense for network boundaries in AWS, allowing unfettered access removes an important part of a cloud security defense-in-depth and makes it easier for adversaries to perform recon on your assets and potentially gain unauthorized access where no other network-based controls exist. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements. Additionally, ensure that Network Firewalls, Route 53 Resolver DNS Firewalls, WAFv2, or some other self-managed host- or network-based appliance exists to interdict and prevent adversarial network traffic from reaching your hosts. Refer to the remediation instructions to remediate this behavior.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Amazon VPC",
                                "AssetComponent": "Security Group"
                            },
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
                                    "ISO 27001:2013 A.13.2.1",
                                    "CIS Amazon Web Services Foundations Benchmark V1.5 5.2",
                                    "CIS Amazon Web Services Foundations Benchmark V1.5 5.3"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    # This is a passing finding - it matches all ports, protocols but doesnt have an open CIDR
                    elif (
                        toPort == toPortTarget
                        and fromPort == fromPortTarget
                        and ipProtocol == targetProtocol
                        and wholeInternetCidr is False
                    ):
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{sgArn}/{ipProtocol}/{checkId}",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": f"{sgArn}/{ipProtocol}/{checkId}",
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
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Amazon VPC",
                                "AssetComponent": "Security Group"
                            },
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
                                    "ISO 27001:2013 A.13.2.1",
                                    "CIS Amazon Web Services Foundations Benchmark V1.5 5.2",
                                    "CIS Amazon Web Services Foundations Benchmark V1.5 5.3",
                                    "CIS Amazon Web Services Foundations Benchmark V2.0 5.2",
                                    "CIS Amazon Web Services Foundations Benchmark V3.0 5.2",
                                    "CIS Amazon Web Services Foundations Benchmark V2.0 5.3",
                                    "CIS Amazon Web Services Foundations Benchmark V3.0 5.3"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    # Skip other non-matching rules
                    else:
                        continue

@registry.register_check("ec2")
def security_group_default_sg_has_rules_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityGroup.3] AWS EC2 default security groups should not have any ingress or egress rules defined"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for secgroup in describe_security_groups(cache, session):
        if secgroup["GroupName"] == "default":
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(secgroup,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            sgName = secgroup["GroupName"]
            sgId = secgroup["GroupId"]
            sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
            # Begin rule eval
            defaultSgAllowsIngress = False
            defaultSgAllowsEgress = False
            # Override the above Bools on the precense of ANY RULES for ingress or egress
            # by Default the Default SG allows unfettered Egress and talk-to-self Ingress
            if secgroup["IpPermissions"]:
                defaultSgAllowsIngress = True
            if secgroup["IpPermissionsEgress"]:
                defaultSgAllowsEgress = True
            # fail on either ingress or egress having rules
            if defaultSgAllowsIngress or defaultSgAllowsEgress:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{sgArn}/default-security-group-has-rules-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{sgArn}/default-security-group-has-rules-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[SecurityGroup.3] The Default Security Group should not have any ingress or egress rules defined",
                    "Description": f"AWS EC2 Security group {sgName} is the default security group and contains one or both of ingress and/or egress rules. Your AWS account automatically has a default security group for the default VPC in each Region. If you don't specify a security group when you launch an instance, the instance is automatically associated with the default security group for the VPC. If you don't want your instances to use the default security group, you can create your own custom security groups and specify them when you launch your instances. It is a best practice to remove ALL rules from the default security groups in case they are automatically attached.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on the default security group refer to the Default and custom security groups section of the Amazon Elastic Compute Cloud User Guide for Linux Instances",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon VPC",
                        "AssetComponent": "Security Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": sgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId}
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
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.4",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.4",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 5.4",
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{sgArn}/default-security-group-has-rules-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{sgArn}/default-security-group-has-rules-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[SecurityGroup.3] The Default Security Group should not have any ingress or egress rules defined",
                    "Description": f"AWS EC2 Security group {sgName} is the default security group and does not define ingress or egress rules.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on the default security group refer to the Default and custom security groups section of the Amazon Elastic Compute Cloud User Guide for Linux Instances",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/default-custom-security-groups.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon VPC",
                        "AssetComponent": "Security Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": sgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2SecurityGroup": {"GroupName": sgName, "GroupId": sgId}
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
                            "ISO 27001:2013 A.13.2.1",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 5.4",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.4",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 5.4",
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        # Skip other SGs
        else:
            continue

## EOF ??