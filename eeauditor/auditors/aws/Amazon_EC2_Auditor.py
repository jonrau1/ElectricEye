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
from botocore.config import Config

# Adding backoff and retries for SSM - this API gets throttled a lot
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

registry = CheckRegister()

def describe_instances(cache, session):
    response = cache.get("describe_instances")
    if response:
        return response
    
    instanceList = []
    
    ec2 = session.client("ec2")
    ssm = session.client("ssm", config=config)
    # Enrich EC2 with SSM details - this is done for the EC2 Auditor - all others using EC2 don't matter too much
    managedInstances = ssm.describe_instance_information()["InstanceInformationList"]

    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": [ 
                        "running",
                        "stopped" 
                    ]
                }
            ]
        ):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                # Skip Spot Instances, based on the fleet ID or status
                try:
                    if i["InstanceLifecycle"] == "spot":
                        continue
                except KeyError:
                    pass
                try:
                    i["SpotInstanceRequestId"]
                    continue
                except KeyError:
                    pass
                # Use a list comprehension to attempt to get SSM info for the instance
                managedInstanceInfo = [mnginst for mnginst in managedInstances if mnginst["InstanceId"] == i["InstanceId"]]
                i["ManagedInstanceInformation"] = managedInstanceInfo
                instanceList.append(i)

        cache["describe_instances"] = instanceList
        return cache["describe_instances"]

@registry.register_check("ec2")
def ec2_imdsv2_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
        # Check specific metadata
        if i["MetadataOptions"]["HttpEndpoint"] == "enabled":
            if i["MetadataOptions"]["HttpTokens"] != "required":
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
        # Check specific metadata
        if i["EnclaveOptions"]["Enabled"] is False:
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
        # Check specific metadata
        if i["SourceDestCheck"] is False:
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
    """[EC2.5] Account-wide EC2 Serial port access should be prohibited unless absolutely required"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    serialDetail = ec2.get_serial_console_access_status()
    serialConsoleArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:serialconsole"
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(serialDetail,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # This is a failing check
    if serialDetail["SerialConsoleAccessEnabled"] is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{serialConsoleArn}/ec2-serial-port-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{serialConsoleArn}/ec2-serial-port-access-check",
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
            "Title": "[EC2.5] Account-wide EC2 Serial port access should be prohibited unless absolutely required",
            "Description": f"AWS Account {awsAccountId} does not restrict access to the EC2 Serial Console in {awsRegion}. The EC2 Serial Console provides text-based access to an instances' serial port as though a monitor and keyboard were attached to it, this can be useful for troubleshooting but can also be abused if not properly restricted, allowing internal and external adversaries unfettered access to the underlying systems within a specific Region. Refer to the remediation instructions if this configuration is not intended",
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
                "AssetComponent": "Serial Console Access"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": serialConsoleArn,
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
            "Id": f"{serialConsoleArn}/ec2-serial-port-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{serialConsoleArn}/ec2-serial-port-access-check",
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
            "Title": "[EC2.5] Account-wide EC2 Serial port access should be prohibited unless absolutely required",
            "Description": f"AWS Account {awsAccountId} does restrict access to the EC2 Serial Console in {awsRegion}.",
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
                "AssetComponent": "Serial Console Access"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": serialConsoleArn,
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
    """[EC2.6] Amazon EC2 Instances should use AMIs that are less than three months old"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
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
                    "Title": "[EC2.5] Amazon EC2 Instances should use AMIs that are less than three months old",
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                    "Title": "[EC2.5] Amazon EC2 Instances should use AMIs that are less than three months old",
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
    """[EC2.7] Amazon EC2 Instances should use AMIs that are currently registered"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
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
                    "Title": "[EC2.6] Amazon EC2 Instances should use AMIs that are currently registered",
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                    "Title": "[EC2.6] Amazon EC2 Instances should use AMIs that are currently registered",
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                    "Title": "[EC2.6] Amazon EC2 Instances should use AMIs that are currently registered",
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
                                    "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
                "Title": "[EC2.6] Amazon EC2 Instances should use AMIs that are currently registered",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat(),
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
    """[EC2.8] Amazon EC2 Instances should be deployed across multiple Availability Zones"""
    ec2 = session.client("ec2")
    # Create empty list to hold unique Subnet IDs - for future lookup against AZs
    uSubnets = []
    # Create another empty list to hold unique AZs based on Subnets
    uAzs = []
    # This list contains regions which have a smaller amount of AZs to begin with - only us-west-1 and the SC2C/C2C regions
    lowerAZRegions = ["us-west-1", "us-isob-east-1", "us-isob-west-1", "us-iso-east-1", "us-iso-west-1"]

    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    assetB64 = None
    # Evaluation time - grab all unique subnets per EC2 instance in Region
    for i in describe_instances(cache, session):
        subnetId = i["SubnetId"]
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
    if awsRegion not in lowerAZRegions and len(uAzs) < 2:
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
            "Title": "[EC2.7] Amazon EC2 Instances should be deployed across multiple Availability Zones",
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
    elif awsRegion in lowerAZRegions and len(uAzs) < 1:
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
            "Title": "[EC2.7] Amazon EC2 Instances should be deployed across multiple Availability Zones",
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
            "Title": "[EC2.7] Amazon EC2 Instances should be deployed across multiple Availability Zones",
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

@registry.register_check("ec2")
def ec2_instance_ssm_managed_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.9] Amazon EC2 instances should be managed by AWS Systems Manager"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]

        # We added the information for SSM DescribeInstanceInformation to each instance in Cache, if the list is empty
        # that means they are not managed at all due to a variety of reasons detailed in the finding...
        if not i["ManagedInstanceInformation"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-managed-by-ssm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.9] Amazon EC2 instances should be managed by AWS Systems Manager",
                "Description": f"EC2 Instance {instanceId} is not managed by AWS Systems Manager. Systems Manager (SSM) enables automated activities such as patching, configuration management, software inventory management and more. Not having instances managed by SSM can degrade the effectiveness of important security processes. This status can be due to the Instance being stopped or hibernated for too long and being removed from SSM tracking, lacking an instance profile that provides permissions to the SSM APIs, or having an SSM Agent that is deprecated. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-managed-by-ssm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.9] Amazon EC2 instances should be managed by AWS Systems Manager",
                "Description": f"EC2 Instance {instanceId} is managed by AWS Systems Manager.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ssm_instace_agent_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.10] Amazon EC2 Linux instances managed by Systems Manager should have the latest SSM Agent installed"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
        # Try to get the platform detail from EC2 directly
        try:
            platform = i["PlatformDetails"]
        except KeyError:
            platform = None

        # We added the information for SSM DescribeInstanceInformation to each instance in Cache, we can
        # use it to build a list comprehension to create a failing or passing state and not ignore all instances
        coverage = [x for x in i["ManagedInstanceInformation"] if x["PlatformType"] == "Linux" and x["IsLatestVersion"] is False]

        if not coverage and platform == "Linux/UNIX":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.10] Amazon EC2 Linux instances managed by Systems Manager should have the latest SSM Agent installed",
                "Description": f"EC2 Instance {instanceId} is a Linux-based platform which does not have the latest SSM Agent installed, or it is not covered by AWS SSM at all. Not having the latest SSM Agent can lead to issues with patching, configuration management, inventory management, and/or vulnerability management activities. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.10] Amazon EC2 Linux instances managed by Systems Manager should have the latest SSM Agent installed",
                "Description": f"EC2 Instance {instanceId} is either a Linux-based platform and has the latest SSM Agent installed or is not a Linux-based platform.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ssm_instance_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.11] Amazon EC2 instances managed by Systems Manager should have a successful Association status"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]

        # We added the information for SSM DescribeInstanceInformation to each instance in Cache, we can
        # use it to build a list comprehension to create a failing or passing state and not ignore all instances
        coverage = [x for x in i["ManagedInstanceInformation"] if x["AssociationStatus"] == "Success"]

        if not coverage:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-ssm-association-success-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.11] Amazon EC2 instances managed by Systems Manager should have a successful Association status",
                "Description": f"EC2 Instance {instanceId} has failed its last Systems Manager State Manager Association or is not onboarded AWS SSM at all. Associations are State Manager automation constructs which encapsulate execution of SSM Documents such as Patching, software configuration, and SSM Agent updates onto an instance. A failed Association can represent the failure of a critical process and should be reviewed. Refer to the remediation instructions for more information on working with State Manager Associations.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-ssm-association-success-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.11] Amazon EC2 instances managed by Systems Manager should have a successful Association status",
                "Description": f"EC2 Instance {instanceId} has passed its last Systems Manager State Manager Association.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ssm_instance_patch_state_state(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.12] Amazon EC2 instances should be be actively managed by and reporting patch information to AWS Systems Manager Patch Manager"""
    ssm = session.client("ssm",config=config)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = i["InstanceId"]
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = i["InstanceType"]
        instanceImage = i["ImageId"]
        subnetId = i["SubnetId"]
        vpcId = i["VpcId"]
        try:
            instanceLaunchedAt = i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"]
        except KeyError:
            instanceLaunchedAt = i["LaunchTime"]
        # Check specific metadata
        r = ssm.describe_instance_patches(InstanceId=instanceId)              
        if not r["Patches"]:
            # This is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-patch-manager-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EC2.12] Amazon EC2 instances should be be actively managed by and reporting patch information to AWS Systems Manager Patch Manager",
                "Description": f"EC2 Instance {instanceId} does not have any patch information recorded and is likely not managed by Patch Manager. Patch Manager automates the installation and application of security, performance, and major version upgrades and KBs onto your instances, reducing exposure to vulnerabilities and other weaknesses. Without automatic patching at scale, vulnerabilities can quickly manifest within a given cloud environment leading to potential avenues of attack for adversaries and other unauthorized actors. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-patch-manager-check",
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
                "Title": "[EC2.12] Amazon EC2 instances should be be actively managed by and reporting patch information to AWS Systems Manager Patch Manager",
                "Description": f"EC2 Instance {instanceId} has patches applied by AWS Systems Manager Patch Manager. You should still review Patch Compliance information to ensure that all required patches were successfully applied.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
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
                                "LaunchedAt": parse(str(instanceLaunchedAt)).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??