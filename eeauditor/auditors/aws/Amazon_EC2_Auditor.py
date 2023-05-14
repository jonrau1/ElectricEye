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
from dateutil.parser import parse
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def describe_instances(cache, session):
    ec2 = session.client("ec2")
    instanceList = []
    response = cache.get("instances")
    if response:
        return response
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name","Values": ["running","stopped"]}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)
        cache["instances"] = instanceList
        return cache["instances"]

@registry.register_check("ec2")
def ec2_imdsv2_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        metadataServiceCheck = str(i["MetadataOptions"]["HttpEndpoint"])
        if metadataServiceCheck == "enabled":
            imdsv2Check = str(i["MetadataOptions"]["HttpTokens"])
            if imdsv2Check != "required":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-imdsv2-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)",
                    "Description": "EC2 Instance "
                    + instanceId
                    + " is not configured to use instance metadata service V2 (IMDSv2). IMDSv2 adds new “belt and suspenders” protections for four types of vulnerabilities that could be used to try to access the IMDS. These new protections go well beyond other types of mitigations, while working seamlessly with existing mitigations such as restricting IAM roles and using local firewall rules to restrict access to the IMDS. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn how to configure IMDSv2 refer to the Transitioning to Using Instance Metadata Service Version 2 section of the Amazon EC2 User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-transition-to-version-2",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-4",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-5",
                            "NIST SP 800-53 Rev. 4 AC-6",
                            "NIST SP 800-53 Rev. 4 AC-14",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "AICPA TSC CC6.3",
                            "ISO 27001:2013 A.6.1.2",
                            "ISO 27001:2013 A.9.1.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.4.1",
                            "ISO 27001:2013 A.9.4.4",
                            "ISO 27001:2013 A.9.4.5"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-imdsv2-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)",
                    "Description": "EC2 Instance "
                    + instanceId
                    + " is using instance metadata service V2 (IMDSv2). IMDSv2 adds new “belt and suspenders” protections for four types of vulnerabilities that could be used to try to access the IMDS. These new protections go well beyond other types of mitigations, while working seamlessly with existing mitigations such as restricting IAM roles and using local firewall rules to restrict access to the IMDS. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn how to configure IMDSv2 refer to the Transitioning to Using Instance Metadata Service Version 2 section of the Amazon EC2 User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#instance-metadata-transition-to-version-2",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            },
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-4",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-5",
                            "NIST SP 800-53 Rev. 4 AC-6",
                            "NIST SP 800-53 Rev. 4 AC-14",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "AICPA TSC CC6.3",
                            "ISO 27001:2013 A.6.1.2",
                            "ISO 27001:2013 A.9.1.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.4.1",
                            "ISO 27001:2013 A.9.4.4",
                            "ISO 27001:2013 A.9.4.5"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        else:
            continue

@registry.register_check("ec2")
def ec2_secure_enclave_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.2] EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        if i["EnclaveOptions"]["Enabled"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-secure-enclave",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.2] EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves",
                "Description": "EC2 Instance "
                + instanceId
                + " is not configured to use a Secure Enclave. AWS Nitro Enclaves is an Amazon EC2 feature that allows you to create isolated execution environments, called enclaves, from Amazon EC2 instances. Enclaves are separate, hardened, and highly constrained virtual machines. They provide only secure local socket connectivity with their parent instance. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Secure Encalves refer to the Getting started: Hello enclave section of the AWS Nitro Enclaves User Guide",
                        "Url": "https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
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
                "Id": instanceArn + "/ec2-secure-enclave",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.2] EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves",
                "Description": "EC2 Instance "
                + instanceId
                + " is configured to use a Secure Enclave.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Secure Encalves refer to the Getting started: Hello enclave section of the AWS Nitro Enclaves User Guide",
                        "Url": "https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
                        },
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "AICPA TSC CC6.3",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ec2_public_facing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.3] EC2 Instances should not be publicly discoverable on the internet"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        # If the Public DNS is not empty that means there is an entry, and that is is public facing
        if str(i["PublicDnsName"]) != "":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-public-facing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.3] EC2 Instances should not be publicly discoverable on the internet",
                "Description": "EC2 Instance "
                + instanceId
                + " is internet-facing (due to having a Public DNS), instances should be behind AWS Elastic Load Balancers, CloudFront Distributions, or a 3rd-party CDN/Load Balancer to avoid any vulnerabilities on the middleware or the operating system from being exploited directly. Additionally, load balancing can increase high availability and resilience of applications hosted on EC2. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/public-load-balancer-private-ec2/"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                            }
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
                        "ISO 27001:2013 A.13.2.1"
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
                "Id": instanceArn + "/ec2-public-facing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EC2.3] EC2 Instances should not be publicly discoverable on the internet",
                "Description": "EC2 Instance "
                + instanceId
                + " is not internet-facing (due to not having a Public DNS).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
                        "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/public-load-balancer-private-ec2/"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ec2_source_dest_verification_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.4] EC2 Instances should use Source-Destination checks unless absolutely not required"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        if i["SourceDestCheck"] == False:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-source-dest-verification-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.4] EC2 Instances should use Source-Destination checks unless absolutely not required",
                "Description": "EC2 Instance "
                + instanceId
                + " does have have the Source-Destination Check enabled. Typically, this is done for self-managed Network Address Translation (NAT), Forward Proxies (such as Squid, for URL Filtering/DNS Protection) or self-managed Firewalls (ModSecurity). These settings should be verified, and underlying technology must be patched to avoid exploits or availability loss. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Source/destination checking refer to the Elastic network interfaces section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
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
                        "ISO 27001:2013 A.13.2.1"
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
                "Id": instanceArn + "/ec2-source-dest-verification-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.4] EC2 Instances should use Source-Destination checks unless absolutely not required",
                "Description": "EC2 Instance "
                + instanceId
                + " has the Source-Destination Check enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Source/destination checking refer to the Elastic network interfaces section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ec2_serial_console_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.5] Serial port access to EC2 should be prohibited unless absolutely required"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    serialDetail = ec2.get_serial_console_access_status()
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(serialDetail,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # This is a failing check
    if serialDetail["SerialConsoleAccessEnabled"] == True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/ec2-serial-port-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion,
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[EC2.5] Serial port access to EC2 should be prohibited unless absolutely required",
            "Description": "AWS Account "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " does not restrict access to the EC2 Serial Console, EC2 Serial Console provides text-based access to an instances’ serial port as though a monitor and keyboard were attached to it, this can be useful for troubleshooting but can also be abused if not properly restricted. Refer to the remediation instructions if this configuration is not intended",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about the EC2 Serial Console refer to the EC2 Serial Console for Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html"
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
                "AssetService": "Amazon EC2",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EC2_Serial_Port_Access_Setting",
                    "Partition": awsPartition,
                    "Region": awsRegion
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
    else:
        # create Sec Hub finding
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + awsRegion + "/ec2-serial-port-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion,
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[EC2.5] Serial port access to EC2 should be prohibited unless absolutely required",
            "Description": "AWS Account "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " restricts access to the EC2 Serial Console.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about the EC2 Serial Console refer to the EC2 Serial Console for Linux instances section of the Amazon Elastic Compute Cloud User Guide",
                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html"
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
                "AssetService": "Amazon EC2",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EC2_Serial_Port_Access_Setting",
                    "Partition": awsPartition,
                    "Region": awsRegion
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

@registry.register_check("ec2")
def ec2_ami_age_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.6] EC2 Instances should use AMIs that are less than 3 months old"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        # Extract the creation date.  As there is only 1 ImageId, there will only be 1 entry. 
        try:
            dsc_image_date = ec2.describe_images(ImageIds=[instanceImage])["Images"][0]["CreationDate"]
            dt_creation_date = parse(dsc_image_date).replace(tzinfo=None)
            AmiAge = datetime.datetime.utcnow() - dt_creation_date

            if AmiAge.days > 90:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-ami-age-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[EC2.5] EC2 Instances should use AMIs that are less than 3 months old",
                    "Description": f"EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.IP-2",
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 SA-3",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "AICPA TSC CC5.2",
                            "AICPA TSC CC7.2",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.8.1.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.14.1.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-ami-age-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EC2.5] EC2 Instances should use AMIs that are less than 3 months old",
                    "Description": f"EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.IP-2",
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 SA-3",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "AICPA TSC CC5.2",
                            "AICPA TSC CC7.2",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.8.1.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.14.1.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except IndexError or KeyError:
            pass

@registry.register_check("ec2")
def ec2_ami_status_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.7] EC2 Instances should use AMIs that are currently registered"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        try:
            amiState = ec2.describe_images(ImageIds=[instanceImage])["Images"][0]["State"]
            if (amiState == "invalid" or
                amiState == "deregistered" or
                amiState == "failed" or
                amiState == "error"):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-registered-ami-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                    "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.IP-2",
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 SA-3",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "AICPA TSC CC5.2",
                            "AICPA TSC CC7.2",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.8.1.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.14.1.1",
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            elif amiState == "available":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-registered-ami-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                    "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.IP-2",
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 SA-3",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "AICPA TSC CC5.2",
                            "AICPA TSC CC7.2",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.8.1.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.14.1.1",
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
            # Pending and Transient states will result in a Low finding - expectation is that registration will eventually succeed
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": instanceArn + "/ec2-registered-ami-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": instanceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                    "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Compute",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Instance"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Instance",
                            "Id": instanceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEc2Instance": {
                                    "Type": instanceType,
                                    "ImageId": instanceImage,
                                    "VpcId": vpcId,
                                    "SubnetId": subnetId,
                                    "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.IP-2",
                            "NIST CSF V1.1 PR.MA-1",
                            "NIST SP 800-53 Rev. 4 SA-3",
                            "NIST SP 800-53 Rev. 4 SI-2",
                            "AICPA TSC CC5.2",
                            "AICPA TSC CC7.2",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.8.1.1",
                            "ISO 27001:2013 A.12.6.1",
                            "ISO 27001:2013 A.14.1.1",
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding                    
        except IndexError or KeyError:
            #failing check, identical to the first finding block.  Depending on timeframe of the deregistration of AMI, describe_images API call may return a blank array
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-ami-status-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: deregistered",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-2",
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 SA-3",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "AICPA TSC CC5.2",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.14.1.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("ec2")
def ec2_concentration_risk(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.8] EC2 Instances should be deployed across multiple Availability Zones"""
    ec2 = session.client("ec2")
    # Create empty list to hold unique Subnet IDs - for future lookup against AZs
    uSubnets = []
    # Create another empty list to hold unique AZs based on Subnets
    uAzs = []
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    assetB64 = None
    # Evaluation time - grab all unique subnets per EC2 instance in Region
    for i in describe_instances(cache, session):
        subnetId = str(i["SubnetId"])
        # write subnets to list if it"s not there
        if subnetId not in uSubnets:
            uSubnets.append(subnetId)
        else:
            continue
    # After done grabbing all subnets, perform super scientific AZ analysis
    for subnet in ec2.describe_subnets(SubnetIds=uSubnets)["Subnets"]:
        azId = str(subnet["AvailabilityZone"])
        if azId not in uAzs:
            uAzs.append(azId)
        else:
            continue
    # Final judgement - need to handle North Cali (us-west-1) separately
    # this is a failing check
    if (awsRegion == "us-west-1" and len(uAzs) < 1):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}:{awsRegion}/ec2-az-resilience-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}:{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[EC2.7] EC2 Instances should be deployed across multiple Availability Zones",
            "Description": f"AWS Account {awsAccountId} in AWS Region {awsRegion} only utilizes {len(uAzs)} Availability Zones for all currently Running and stopped EC2 Instances. To maintain a higher standard of cyber resilience you should use at least 3 (or 2 in North California) to host your workloads on. If your applications required higher cyber resilience standards refer to the remediation instructions for more information.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about cyber resilience and reliability, such as the usage of multi-AZ architecture, refer to the Reliability Pillar of AWS Well-Architected Framework",
                    "Url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html"
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
                "AssetService": "AWS Account",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EC2_Concentration_Risk",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a failing check
    elif (awsRegion != "us-west-1" and len(uAzs) < 2):
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}:{awsRegion}/ec2-az-resilience-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}:{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[EC2.7] EC2 Instances should be deployed across multiple Availability Zones",
            "Description": f"AWS Account {awsAccountId} in AWS Region {awsRegion} only utilizes {len(uAzs)} Availability Zones for all currently Running and stopped EC2 Instances. To maintain a higher standard of cyber resilience you should use at least 3 (or 2 in North California) to host your workloads on. If your applications required higher cyber resilience standards refer to the remediation instructions for more information.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about cyber resilience and reliability, such as the usage of multi-AZ architecture, refer to the Reliability Pillar of AWS Well-Architected Framework",
                    "Url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html"
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
                "AssetService": "AWS Account",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EC2_Concentration_Risk",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}:{awsRegion}/ec2-az-resilience-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}:{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": [ "Software and Configuration Checks/AWS Security Best Practices" ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[EC2.7] EC2 Instances should be deployed across multiple Availability Zones",
            "Description": f"AWS Account {awsAccountId} in AWS Region {awsRegion} utilizes {len(uAzs)} Availability Zones for all currently Running and stopped EC2 Instances which can help maintain a higher standard of cyber resilience.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To learn more about cyber resilience and reliability, such as the usage of multi-AZ architecture, refer to the Reliability Pillar of AWS Well-Architected Framework",
                    "Url": "https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html"
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
                "AssetService": "AWS Account",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EC2_Concentration_Risk",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.BE-5",
                    "NIST CSF V1.1 PR.PT-5",
                    "NIST SP 800-53 Rev. 4 CP-2",
                    "NIST SP 800-53 Rev. 4 CP-11",
                    "NIST SP 800-53 Rev. 4 SA-13",
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding