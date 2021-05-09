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
from dateutil.parser import parse

registry = CheckRegister()

ec2 = boto3.client("ec2")

def paginate(cache):
    response = cache.get("paginate")
    if response:
        return response
    get_paginators = ec2.get_paginator("describe_instances")
    if get_paginators:
        cache["paginate"] = get_paginators.paginate(Filters=[{'Name': 'instance-state-name','Values': ['running','stopped']}])
        return cache["paginate"]

@registry.register_check("ec2")
def ec2_imdsv2_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.1] EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginate(cache=cache)
        for page in iterator:
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceId = str(i["InstanceId"])
                    instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                    instanceType = str(i["InstanceType"])
                    instanceImage = str(i["ImageId"])
                    subnetId = str(i["SubnetId"])
                    vpcId = str(i["VpcId"])
                    instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                    metadataServiceCheck = str(i["MetadataOptions"]["HttpEndpoint"])
                    if metadataServiceCheck == "enabled":
                        imdsv2Check = str(i["MetadataOptions"]["HttpTokens"])
                        if imdsv2Check != "required":
                            try:
                                # create Sec Hub finding
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
                                    "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "NIST CSF PR.AC-4",
                                            "NIST SP 800-53 AC-1",
                                            "NIST SP 800-53 AC-2",
                                            "NIST SP 800-53 AC-3",
                                            "NIST SP 800-53 AC-5",
                                            "NIST SP 800-53 AC-6",
                                            "NIST SP 800-53 AC-14",
                                            "NIST SP 800-53 AC-16",
                                            "NIST SP 800-53 AC-24",
                                            "AICPA TSC CC6.3",
                                            "ISO 27001:2013 A.6.1.2",
                                            "ISO 27001:2013 A.9.1.2",
                                            "ISO 27001:2013 A.9.2.3",
                                            "ISO 27001:2013 A.9.4.1",
                                            "ISO 27001:2013 A.9.4.4",
                                            "ISO 27001:2013 A.9.4.5",
                                        ]
                                    },
                                    "Workflow": {"Status": "NEW"},
                                    "RecordState": "ACTIVE",
                                }
                                yield finding
                            except Exception as e:
                                print(e)
                        else:
                            try:
                                # create Sec Hub finding
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
                                    "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "NIST CSF PR.AC-4",
                                            "NIST SP 800-53 AC-1",
                                            "NIST SP 800-53 AC-2",
                                            "NIST SP 800-53 AC-3",
                                            "NIST SP 800-53 AC-5",
                                            "NIST SP 800-53 AC-6",
                                            "NIST SP 800-53 AC-14",
                                            "NIST SP 800-53 AC-16",
                                            "NIST SP 800-53 AC-24",
                                            "AICPA TSC CC6.3",
                                            "ISO 27001:2013 A.6.1.2",
                                            "ISO 27001:2013 A.9.1.2",
                                            "ISO 27001:2013 A.9.2.3",
                                            "ISO 27001:2013 A.9.4.1",
                                            "ISO 27001:2013 A.9.4.4",
                                            "ISO 27001:2013 A.9.4.5",
                                        ]
                                    },
                                    "Workflow": {"Status": "RESOLVED"},
                                    "RecordState": "ARCHIVED",
                                }
                                yield finding
                            except Exception as e:
                                print(e)
                    else:
                        pass
    except Exception as e:
        print(e)

@registry.register_check("ec2")
def ec2_secure_enclave_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.2] EC2 Instances should be configured to use Secure Enclaves"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginate(cache=cache)
        for page in iterator:
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceId = str(i["InstanceId"])
                    instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                    instanceType = str(i["InstanceType"])
                    instanceImage = str(i["ImageId"])
                    subnetId = str(i["SubnetId"])
                    vpcId = str(i["VpcId"])
                    instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                    if str(i["EnclaveOptions"]["Enabled"]) == "False":
                        # create Sec Hub finding
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
                            "Title": "[EC2.2] EC2 Instances should be configured to use Secure Enclaves",
                            "Description": "EC2 Instance "
                            + instanceId
                            + " is not configured to use a Secure Enclave. AWS Nitro Enclaves is an Amazon EC2 feature that allows you to create isolated execution environments, called enclaves, from Amazon EC2 instances. Enclaves are separate, hardened, and highly constrained virtual machines. They provide only secure local socket connectivity with their parent instance. Refer to the remediation instructions if this configuration is not intended",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn how to configure Secure Encalves refer to the Getting started: Hello enclave section of the AWS Nitro Enclaves User Guide",
                                    "Url": "https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-4",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-2",
                                    "NIST SP 800-53 AC-3",
                                    "NIST SP 800-53 AC-5",
                                    "NIST SP 800-53 AC-6",
                                    "NIST SP 800-53 AC-14",
                                    "NIST SP 800-53 AC-16",
                                    "NIST SP 800-53 AC-24",
                                    "AICPA TSC CC6.3",
                                    "ISO 27001:2013 A.6.1.2",
                                    "ISO 27001:2013 A.9.1.2",
                                    "ISO 27001:2013 A.9.2.3",
                                    "ISO 27001:2013 A.9.4.1",
                                    "ISO 27001:2013 A.9.4.4",
                                    "ISO 27001:2013 A.9.4.5",
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": instanceArn + "/ec2-enclave-check",
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
                            "Title": "[EC2.2] EC2 Instances should be configured to use Secure Enclaves",
                            "Description": "EC2 Instance "
                            + instanceId
                            + " is configured to use a Secure Enclave.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn how to configure Secure Encalves refer to the Getting started: Hello enclave section of the AWS Nitro Enclaves User Guide",
                                    "Url": "https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-4",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-2",
                                    "NIST SP 800-53 AC-3",
                                    "NIST SP 800-53 AC-5",
                                    "NIST SP 800-53 AC-6",
                                    "NIST SP 800-53 AC-14",
                                    "NIST SP 800-53 AC-16",
                                    "NIST SP 800-53 AC-24",
                                    "AICPA TSC CC6.3",
                                    "ISO 27001:2013 A.6.1.2",
                                    "ISO 27001:2013 A.9.1.2",
                                    "ISO 27001:2013 A.9.2.3",
                                    "ISO 27001:2013 A.9.4.1",
                                    "ISO 27001:2013 A.9.4.4",
                                    "ISO 27001:2013 A.9.4.5",
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
    except Exception as e:
        print(e)

@registry.register_check("ec2")
def ec2_public_facing_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.3] EC2 Instances should not be internet-facing"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginate(cache=cache)
        for page in iterator:
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceId = str(i["InstanceId"])
                    instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                    instanceType = str(i["InstanceType"])
                    instanceImage = str(i["ImageId"])
                    subnetId = str(i["SubnetId"])
                    vpcId = str(i["VpcId"])
                    instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                    # If the Public DNS is not empty that means there is an entry, and that is is public facing
                    if str(i["PublicDnsName"]) != "":
                        # create Sec Hub finding
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
                            "Title": "[EC2.3] EC2 Instances should not be internet-facing",
                            "Description": "EC2 Instance "
                            + instanceId
                            + " is internet-facing (due to having a Public DNS), instances should be behind Load Balancers or CloudFront distrobutions to avoid any vulnerabilities on the middleware or the operating system from being exploited directly and to increase high availability and resilience of applications hosted on EC2. Refer to the remediation instructions if this configuration is not intended",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
                                    "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/public-load-balancer-private-ec2/"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    else:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": instanceArn + "/ec2-enclave-check",
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
                            "Title": "[EC2.3] EC2 Instances should not be internet-facing",
                            "Description": "EC2 Instance "
                            + instanceId
                            + " is not internet-facing (due to not having a Public DNS).",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
                                    "Url": "https://aws.amazon.com/premiumsupport/knowledge-center/public-load-balancer-private-ec2/"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
    except Exception as e:
        print(e)

@registry.register_check("ec2")
def ec2_source_dest_verification_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.4] EC2 Instances should use Source-Destination checks unless absolutely not required"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginate(cache=cache)
        for page in iterator:
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceId = str(i["InstanceId"])
                    instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                    instanceType = str(i["InstanceType"])
                    instanceImage = str(i["ImageId"])
                    subnetId = str(i["SubnetId"])
                    vpcId = str(i["VpcId"])
                    instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                    # If the Public DNS is not empty that means there is an entry, and that is is public facing
                    if str(i["SourceDestCheck"]) == "False":
                        # create Sec Hub finding
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
                            + " does have have the Source-Destination Check enabled. Typically, this is done for self-managed Network Address Translation (NAT), Forward Proxies (such as Squid, for URL Filtering/DNS Protection) or self-managed Firewalls (ModSecurity). These settings should be verified, and underlying technology must be patched to avoid exploits or availability loss. Refer to the remediation instructions if this configuration is not intended",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about Source/destination checking refer to the Elastic network interfaces section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#eni-basics"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
    except Exception as e:
        print(e)


@registry.register_check("ec2")
def ec2_serial_console_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.5] Serial port access to EC2 should be prohibited unless absolutely required"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # This is a failing check
    if str(ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]) == "True":
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
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": awsAccountId,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF PR.AC-3",
                    "NIST SP 800-53 AC-1",
                    "NIST SP 800-53 AC-17",
                    "NIST SP 800-53 AC-19",
                    "NIST SP 800-53 AC-20",
                    "NIST SP 800-53 SC-15",
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
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": awsAccountId,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.AC-3",
                    "NIST SP 800-53 AC-1",
                    "NIST SP 800-53 AC-17",
                    "NIST SP 800-53 AC-19",
                    "NIST SP 800-53 AC-20",
                    "NIST SP 800-53 SC-15",
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
def ec2_ami_age_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.5] EC2 Instances should use AMIs that are less than 6 months old"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    iterator = paginate(cache=cache)
    for page in iterator:
        for r in page["Reservations"]:
            for i in r["Instances"]:
                instanceId = str(i["InstanceId"])
                instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                instanceType = str(i["InstanceType"])
                instanceImage = str(i["ImageId"])
                subnetId = str(i["SubnetId"])
                vpcId = str(i["VpcId"])
                instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                # Extract the creation date.  As there is only 1 ImageId, there will only be 1 entry. 
                try:
                    dsc_image_date = ec2.describe_images(ImageIds=[instanceImage])['Images'][0]['CreationDate']
                    dt_creation_date = parse(dsc_image_date).replace(tzinfo=None)
                    AmiAge = datetime.datetime.utcnow() - dt_creation_date

                    if AmiAge.days > 180:
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
                            "Title": "[EC2.5] EC2 Instances should use AMIs that are less than 6 months old",
                            "Description": f"EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "AmiAge": f"{AmiAge.days} days old",
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
                                    "NIST CSF PR.IP-2",
                                    "NIST CSF PR.MA-1",
                                    "NIST SP 800-53 SA-3",
                                    "NIST SP 800-53 SI-2",
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
                            "Title": "[EC2.5] EC2 Instances should use AMIs that are less than 6 months old",
                            "Description": f"EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "AmiAge": f"{AmiAge.days} days old",
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
                                    "NIST CSF PR.IP-2",
                                    "NIST CSF PR.MA-1",
                                    "NIST SP 800-53 SA-3",
                                    "NIST SP 800-53 SI-2",
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
                except IndexError or KeyError:
                    pass


@registry.register_check("ec2")
def ec2_ami_status_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.6] EC2 Instances should use AMIs that are currently registered"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    iterator = paginate(cache=cache)
    for page in iterator:
        for r in page["Reservations"]:
            for i in r["Instances"]:
                instanceId = str(i["InstanceId"])
                instanceArn = (f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                instanceType = str(i["InstanceType"])
                instanceImage = str(i["ImageId"])
                subnetId = str(i["SubnetId"])
                vpcId = str(i["VpcId"])
                instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                try:
                    dsc_image_state = ec2.describe_images(ImageIds=[instanceImage])['Images'][0]['State']
                    if dsc_image_state == 'invalid' or \
                        dsc_image_state == 'deregistered' or \
                        dsc_image_state == 'failed' or \
                        dsc_image_state == 'error':
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
                            "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {dsc_image_state}",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "AmiStatus": f"{dsc_image_state}",
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
                                    "NIST CSF PR.IP-2",
                                    "NIST CSF PR.MA-1",
                                    "NIST SP 800-53 SA-3",
                                    "NIST SP 800-53 SI-2",
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
                    elif dsc_image_state == 'available':
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
                            "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                            "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {dsc_image_state}",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "AmiStatus": f"{dsc_image_state}",
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
                                    "NIST CSF PR.IP-2",
                                    "NIST CSF PR.MA-1",
                                    "NIST SP 800-53 SA-3",
                                    "NIST SP 800-53 SI-2",
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
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[EC2.6] EC2 Instances should use AMIs that are currently registered",
                            "Description": f"EC2 Instance {instanceId} is using an AMI that has a status of: {dsc_image_state}",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about AMI usage, refer to the AMI section of the Amazon Elastic Compute Cloud User Guide",
                                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/deregister-ami.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                            "AmiStatus": f"{dsc_image_state}",
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
                                    "NIST CSF PR.IP-2",
                                    "NIST CSF PR.MA-1",
                                    "NIST SP 800-53 SA-3",
                                    "NIST SP 800-53 SI-2",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                                        "AmiStatus": f"Deregistered",
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
                                "NIST CSF PR.IP-2",
                                "NIST CSF PR.MA-1",
                                "NIST SP 800-53 SA-3",
                                "NIST SP 800-53 SI-2",
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