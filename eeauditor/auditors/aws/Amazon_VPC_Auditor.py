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
import datetime
import base64
import json

registry = CheckRegister()

def describe_vpcs(cache, session):
    response = cache.get("describe_vpcs")
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)["Vpcs"]
    return cache["describe_vpcs"]

def describe_verified_access_instances(cache, session):
    response = cache.get("describe_verified_access_instances")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_verified_access_instances"] = ec2.describe_verified_access_instances(DryRun=False)["VerifiedAccessInstances"]
    return cache["describe_verified_access_instances"]

def get_verified_access_instance_logging_configuration(session, verifiedInstanceId):
    ec2 = session.client("ec2")

    return ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[verifiedInstanceId]
    )["LoggingConfigurations"]

def check_verified_access_instance_web_acl_protection(session, verifiedInstanceArn):
    wafv2 = session.client("wafv2")

    try:
        if "WebACL" in wafv2.get_web_acl_for_resource(ResourceArn=verifiedInstanceArn):
            return True
        else:
            return False
    except Exception:
        return False
    
def describe_network_interfaces(cache, session):
    response = cache.get("describe_network_interfaces")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_network_interfaces"] = ec2.describe_network_interfaces(DryRun=False, MaxResults=500)["NetworkInterfaces"]
    return cache["describe_network_interfaces"]

def describe_network_acls(cache, session):
    response = cache.get("describe_network_acls")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_network_acls"] = ec2.describe_network_acls()["NetworkAcls"]
    return cache["describe_network_acls"]

def describe_vpc_endpoints(cache, session):
    response = cache.get("describe_vpc_endpoints")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_vpc_endpoints"] = ec2.describe_vpc_endpoints()["VpcEndpoints"]
    return cache["describe_vpc_endpoints"]

def check_vpc_endpoint_policy_support(cache, session):
    response = cache.get("check_vpc_endpoint_policy_support")
    
    if response:
        return response
    
    ec2 = session.client("ec2")
    # Return VPC Endpoint service names that support Endpoint Policies
    supportedServices = [
        endpoint["ServiceName"] for endpoint in ec2.describe_vpc_endpoint_services()["ServiceDetails"] if endpoint["VpcEndpointPolicySupported"] is True
    ]

    cache["check_vpc_endpoint_policy_support"] = supportedServices
    return cache["check_vpc_endpoint_policy_support"]

@registry.register_check("ec2")
def aws_vpc_is_default_vpc_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.1] Amazon Virtual Private Clouds (VPCs) that are the Default VPC and are unused should be deleted"""
    for vpcs in describe_vpcs(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpcs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpcId = vpcs["VpcId"]
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if vpcs["IsDefault"] is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vpcArn}/aws-vpc-is-default-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vpcArn}/aws-vpc-is-default-vpc-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.1] Amazon Virtual Private Clouds (VPCs) that are the Default VPC and are unused should be deleted",
                "Description": f"Amazon VPC {vpcId} has been identified as the Default VPC, consider deleting this VPC if it is not necessary for daily operations. The Default VPC in AWS Regions not typically used can serve as a persistence area for malicious actors, additionally, many services will automatically use this VPC which can lead to a degraded security posture. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Virtual Private Cloud"
                },
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
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vpcArn}/aws-vpc-is-default-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vpcArn}/aws-vpc-is-default-vpc-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.1] Amazon Virtual Private Clouds (VPCs) that are the Default VPC and are unused should be deleted",
                "Description": f"Amazon VPC {vpcId} is not the Default VPC.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html#deleting-default-vpc",
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Virtual Private Cloud"
                },
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
                        "NIST CSF V1.1 PR.DS-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 MP-6",
                        "NIST SP 800-53 Rev. 4 PE-16",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.5",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.8.3.1",
                        "ISO 27001:2013 A.8.3.2",
                        "ISO 27001:2013 A.8.3.3",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("ec2")
def aws_vpc_flow_logs_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.2] Amazon Virtual Private Cloud (VPC) flow logs should be enabled for all Amazon Virtual Private Cloud (VPC)s"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpcs in describe_vpcs(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpcs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpcId = vpcs["VpcId"]
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # this is a failing check
        if not ec2.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpcId]}])["FlowLogs"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vpcArn}/vpc-flow-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vpcArn}/vpc-flow-log-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.2] Amazon Virtual Private Cloud (VPC) flow logs should be enabled for all Amazon Virtual Private Cloud (VPC)s",
                "Description": f"Amazon Virtual Private Cloud (VPC) {vpcId} does not have flow logging enabled. VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. Flow log data can be published to the following locations: Amazon CloudWatch Logs, Amazon S3, or Amazon Kinesis Data Firehose. After you create a flow log, you can retrieve and view the flow log records in the log group, bucket, or delivery stream that you configured. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Virtual Private Cloud"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"VpcId": vpcId}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.9",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.9",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vpcArn}/vpc-flow-log-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vpcArn}/vpc-flow-log-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.2] Amazon Virtual Private Cloud (VPC) flow logs should be enabled for all Amazon Virtual Private Cloud (VPC)s",
                "Description": f"Amazon Virtual Private Cloud (VPC) {vpcId} does have flow logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on flow logs refer to the VPC Flow Logs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Virtual Private Cloud"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"VpcId": vpcId}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 3.9",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.9",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 3.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_subnet_public_ip_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.3] Amazon Virtual Private Cloud (VPC) subnets should not automatically map Public IP addresses on launch"""
    ec2 = session.client("ec2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpcs in describe_vpcs(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpcs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpcId = vpcs["VpcId"]
        # Get subnets for the VPC
        for snet in ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values': [vpcId]}])["Subnets"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(snet,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            snetArn = snet["SubnetArn"]
            snetId = snet["SubnetId"]
            if snet["MapPublicIpOnLaunch"] is True:
                # This is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{snetArn}/subnet-map-public-ip-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{snetArn}/subnet-map-public-ip-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[VPC.3] Amazon Virtual Private Cloud (VPC) subnets should not automatically map Public IP addresses on launch",
                    "Description": f"Amazon Virtual Private Cloud (VPC) subnet {snetId} maps Public IPs on Launch, consider disabling this to avoid unncessarily exposing workloads to the internet. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
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
                        "AssetService": "Amazon Virtual Private Cloud",
                        "AssetComponent": "Subnet"
                    },
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
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.1.3",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{snetArn}/subnet-map-public-ip-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{snetArn}/subnet-map-public-ip-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[VPC.3] Amazon Virtual Private Cloud (VPC) subnets should not automatically map Public IP addresses on launch",
                    "Description": f"Amazon Virtual Private Cloud (VPC) subnet {snetId} does not map Public IPs on launch.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
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
                        "AssetService": "Amazon Virtual Private Cloud",
                        "AssetComponent": "Subnet"
                    },
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
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
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
def aws_subnet_no_ip_space_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.4] Amazon Virtual Private Cloud (VPC) subnets should be monitored for available IP address space"""
    ec2 = session.client("ec2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpcs in describe_vpcs(cache, session):
        vpcId = vpcs["VpcId"]
        # Get subnets for the VPC
        for snet in ec2.describe_subnets(Filters=[{'Name': 'vpc-id','Values': [vpcId]}])["Subnets"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(snet,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            snetArn = snet["SubnetArn"]
            snetId = snet["SubnetId"] 
            if int(snet["AvailableIpAddressCount"]) <= 1:
                # This is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{snetArn}/subnet-no-remaining-ip-space-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{snetArn}/subnet-no-remaining-ip-space-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[VPC.4] Amazon Virtual Private Cloud (VPC) subnets should be monitored for available IP address space",
                    "Description": f"Amazon Virtual Private Cloud (VPC) subnet {snetId} does not have any available IP address space, consider terminating unncessary workloads, adding a Secondary CIDR to the parent VPC, or expanding CIDR capacity to avoid availability losses. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
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
                        "AssetService": "Amazon Virtual Private Cloud",
                        "AssetComponent": "Subnet"
                    },
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
                            "NIST CSF V1.1 ID.BE-5",
                            "NIST CSF V1.1 PR.DS-4",
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 AU-4",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-7",
                            "NIST SP 800-53 Rev. 4 CP-8",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 CP-13",
                            "NIST SP 800-53 Rev. 4 PL-8",
                            "NIST SP 800-53 Rev. 4 SA-14",
                            "NIST SP 800-53 Rev. 4 SC-5",
                            "NIST SP 800-53 Rev. 4 SC-6",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.12.3.1",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{snetArn}/subnet-no-remaining-ip-space-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{snetArn}/subnet-no-remaining-ip-space-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[VPC.4] Amazon Virtual Private Cloud (VPC) subnets should be monitored for available IP address space",
                    "Description": f"Amazon Virtual Private Cloud (VPC) subnet {snetId} does have available IP address space.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on IP addressing refer to the IP Addressing in your VPC section of the Amazon Virtual Private Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"
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
                        "AssetService": "Amazon Virtual Private Cloud",
                        "AssetComponent": "Subnet"
                    },
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
                            "NIST CSF V1.1 ID.BE-5",
                            "NIST CSF V1.1 PR.DS-4",
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 AU-4",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-7",
                            "NIST SP 800-53 Rev. 4 CP-8",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 CP-13",
                            "NIST SP 800-53 Rev. 4 PL-8",
                            "NIST SP 800-53 Rev. 4 SA-14",
                            "NIST SP 800-53 Rev. 4 SC-5",
                            "NIST SP 800-53 Rev. 4 SC-6",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.12.3.1",
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
def aws_verified_access_instances_logging_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.5] AWS Verified Access instances should have at least one logging configuration source enabled"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instance in describe_verified_access_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vaiId = instance["VerifiedAccessInstanceId"]
        vaiArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:verified-access-instance/{vaiId}"
        # Retrieve & check logging - if any one of the destinations are enabled this will pass
        loggingConfig = get_verified_access_instance_logging_configuration(session, vaiId)
        enabledLogs = [config["AccessLogs"][service]["Enabled"] for config in loggingConfig for service in config["AccessLogs"]]
        # This is a failing check
        if any(enabledLogs) is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vaiArn}/aws-verified-access-instances-logging-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-logging-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[VPC.5] AWS Verified Access instances should have at least one logging configuration source enabled",
                "Description": f"Verified Access instance {vaiId} does not have any of the possible logging destinations enabled. After AWS Verified Access evaluates each access request, it logs all access attempts. This provides centralized visibility into application access and helps you quickly respond to security incidents and audit requests. Verified Access supports the following destinations for publishing access logs: Amazon CloudWatch Logs log groups, Amazon S3 buckets, and/or Amazon Kinesis Data Firehose delivery streams. Verified Access supports the Open Cybersecurity Schema Framework (OCSF) logging format for storage in AWS Security Lake or other data warehouse or data lakes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on enabling logging for your Verified Access instances refer to the Enable Verified Access logs section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/access-logs-enable.html"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vaiArn}/aws-verified-access-instances-logging-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-logging-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.5] AWS Verified Access instances should have at least one logging configuration source enabled",
                "Description": f"Verified Access instance {vaiId} does have at least one of the possible logging destinations enabled. The logging configuration is as follows: {str(loggingConfig)}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on enabling logging for your Verified Access instances refer to the Enable Verified Access logs section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/access-logs-enable.html"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_verified_access_instances_trust_provider_associated_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.6] AWS Verified Access instances should be associated with a Verified Access trust provider"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instance in describe_verified_access_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vaiId = instance["VerifiedAccessInstanceId"]
        vaiArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:verified-access-instance/{vaiId}"
        # This is a failing check
        if not instance["VerifiedAccessTrustProviders"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vaiArn}/aws-verified-access-instances-trust-provider-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-trust-provider-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[VPC.6] AWS Verified Access instances should be associated with a Verified Access trust provider",
                "Description": f"Verified Access instance {vaiId} does not have any Verified Access trust providers associated. A trust provider is a service that sends information about users and devices, called trust data, to AWS Verified Access. Trust data may include attributes based on user identity such as an email address or membership in the 'sales' organization, or device management information such as security patches or antivirus software version. Verified Access instances without trust providers associated may not be in-use and should be removed as non-compliant providers may be inadvertently (or rarely, maliciously) attached. Ensuring only the right amount of assets are provisioned and are in-use is an important part of long term healthy asset management and cyber hygeine. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on attaching trust providers to your Verified Access instances refer to the Tutorial: Getting started with Verified Access section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/getting-started.html#getting-started-step3"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
                "Id": f"{vaiArn}/aws-verified-access-instances-trust-provider-association-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-trust-provider-association-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.6] AWS Verified Access instances should be associated with a Verified Access trust provider",
                "Description": f"Verified Access instance {vaiId} does not have a Verified Access trust provider associated.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on attaching trust providers to your Verified Access instances refer to the Tutorial: Getting started with Verified Access section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/getting-started.html#getting-started-step3"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "ARCHIVED",
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
def aws_verified_access_instances_wafv2_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.7] AWS Verified Access instances should be protected by an AWS WAFv2 Web ACL"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for instance in describe_verified_access_instances(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(instance,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vaiId = instance["VerifiedAccessInstanceId"]
        vaiArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:verified-access-instance/{vaiId}"
        # This is a failing check
        if check_verified_access_instance_web_acl_protection(session, vaiArn) is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vaiArn}/aws-verified-access-instances-wafv2-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-wafv2-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.7] AWS Verified Access instances should be protected by an AWS WAFv2 Web ACL",
                "Description": f"Verified Access instance {vaiId} does not have an AWS WAFv2 Web ACL associated with it. In addition to the authentication and authorization rules enforced by Verified Access, you may also want to apply perimeter protection. This can help you protect your applications from additional threats. You can accomplish this by integrating AWS WAF into your Verified Access deployment. AWS WAF is a web application firewall that lets you monitor the HTTP(S) requests that are forwarded to your protected web application resources. You can integrate AWS WAF with Verified Access by associating an AWS WAF web access control list (ACL) with a Verified Access instance. A web ACL is a AWS WAF resource that gives you fine-grained control over all of the HTTP(S) web requests that your protected resource responds to. While the AWS WAF association or disassociation request is being processed, the status of any Verified Access endpoints attached to the instance are shown as updating. After the request is complete, the status returns to active. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on attaching WAFv2 Web ACLs to your Verified Access instances refer to the Integrating with AWS WAF section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/waf-integration.html"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{vaiArn}/aws-verified-access-instances-wafv2-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{vaiArn}/aws-verified-access-instances-wafv2-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.7] AWS Verified Access instances should be protected by an AWS WAFv2 Web ACL",
                "Description": f"Verified Access instance {vaiId} does have an AWS WAFv2 Web ACL associated with it.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on attaching WAFv2 Web ACLs to your Verified Access instances refer to the Integrating with AWS WAF section of the AWS Verified Access User Guide",
                        "Url": "https://docs.aws.amazon.com/verified-access/latest/ug/waf-integration.html"
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
                    "AssetService": "AWS Verified Access",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VerifiedAccessInstance",
                        "Id": vaiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_eni_attached_in_use_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.8] Amazon Elastic Network Interfaces (ENIs) should be attached and in-use"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for eni in describe_network_interfaces(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(eni,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        eniId = eni["NetworkInterfaceId"]
        eniArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:network-interface/{eniId}"
        # This is a failing check
        if "Attachment" not in eni:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{eniArn}/aws-eni-attached-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eniArn}/aws-eni-attached-in-use-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[VPC.8] Amazon Elastic Network Interfaces (ENIs) should be attached and in-use",
                "Description": f"Elastic Network Interface (ENI) {eniId} is not in an attached and in-use state. An elastic network interface is a logical networking component in a VPC that represents a virtual network card, you can create and configure network interfaces and attach them to instances in the same Availability Zone. Your account might also have requester-managed network interfaces, which are created and managed by AWS services to enable you to use other resources and services. You cannot manage these network interfaces yourself. Even when in a detached state, ENIs consume IP space and quota limits within your Account and Region, and should be deleted when not in use. In rarer circumstances, adversaries and malicious insiders can attach secondary interfaces to other resources to masquerade as another resource or otherwise evade detection and defenses looking for new IPs or new activity. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on ENIs and how to manage them refer to the Elastic network interfaces section of the Amazon Elastic Compute Cloud User Guide for Linux Instances",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Interface"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkInterface",
                        "Id": eniArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkInterface": {
                                "NetworkInterfaceId": eniId
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
                "Id": f"{eniArn}/aws-eni-attached-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eniArn}/aws-eni-attached-in-use-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.8] Amazon Elastic Network Interfaces (ENIs) should be attached and in-use",
                "Description": f"Elastic Network Interface (ENI) {eniId} is in an attached and in-use state.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on ENIs and how to manage them refer to the Elastic network interfaces section of the Amazon Elastic Compute Cloud User Guide for Linux Instances",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Interface"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkInterface",
                        "Id": eniArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkInterface": {
                                "NetworkInterfaceId": eniId
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
def aws_network_acl_allow_unrestricted_ssh_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.9] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Secure Shell (SSH) protocol"""
    protocolPort = 22
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for nacl in describe_network_acls(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(nacl,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        naclId = nacl["NetworkAclId"]
        naclArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:network-acl/{naclId}"
        # Evaluate the rules within the NACL - this check will fail on either IPv4 or IPv6 with only the specified protocol
        # as the default rules within a NACL are the "last place" DENY ALL and "first place" ALLOW ALL
        # this is only for CIS Benchmarking, as using NACLs is not considered best practice anymore, depending on what you're doing
        unrestrictedAccess = False
        for entry in nacl["Entries"]:
            egress = entry.get("Egress", False)
            ipV4CidrBlock = entry.get("CidrBlock")
            ipV6CidrBlock = entry.get("Ipv6CidrBlock")
            portRange = entry.get("PortRange", {})
            fromPort = portRange.get("From")
            toPort = portRange.get("To")
            # Override Bool if any IPv4 or IPv6 allows ingress
            if (
                not egress
                and (
                    ipV4CidrBlock == "0.0.0.0/0"
                    or ipV6CidrBlock == "::/0"
                )
                and (fromPort == protocolPort)
                and (toPort == protocolPort)
            ):
                unrestrictedAccess = True
                break
        # this is a failing finding
        if unrestrictedAccess is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{naclArn}/network-acl-allows-unrestricted-ssh-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{naclArn}/network-acl-allows-unrestricted-ssh-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.9] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Secure Shell (SSH) protocol",
                "Description": f"Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) {naclId} allows unrestricted ingress to SSH (TCP Port 22) to either IPv4 or IPv6 public CIDRs. A network access control list (ACL) allows or denies specific inbound or outbound traffic at the subnet level. You can use the default network ACL for your VPC, or you can create a custom network ACL for your VPC with rules that are similar to the rules for your security groups in order to add an additional layer of security to your VPC. You can create a custom network ACL and associate it with a subnet to allow or deny specific inbound or outbound traffic at the subnet level. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring NACLs for your Subnets refer to the Control traffic to subnets using network ACLs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-ephemeral-ports"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Access Control List"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkAcl",
                        "Id": naclArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkAcl": {
                                "NetworkAclId": naclId,
                                "VpcId": nacl["VpcId"],
                                "OwnerId": nacl["OwnerId"],
                                "Entries": nacl["Entries"]
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
                        "CIS Amazon Web Services Foundations Benchmark V1.5 5.1",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 5.1",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 5.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{naclArn}/network-acl-allows-unrestricted-ssh-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{naclArn}/network-acl-allows-unrestricted-ssh-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.9] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Secure Shell (SSH) protocol",
                "Description": f"Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) {naclId} does not allow unrestricted ingress to SSH (TCP Port 22) to either IPv4 or IPv6 public CIDRs.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring NACLs for your Subnets refer to the Control traffic to subnets using network ACLs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-ephemeral-ports"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Access Control List"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkAcl",
                        "Id": naclArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkAcl": {
                                "NetworkAclId": naclId,
                                "VpcId": nacl["VpcId"],
                                "OwnerId": nacl["OwnerId"],
                                "Entries": nacl["Entries"]
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
                        "CIS Amazon Web Services Foundations Benchmark V1.5 5.1",
                        "CIS Amazon Web Services Foundations Benchmark V2.0 5.1",
                        "CIS Amazon Web Services Foundations Benchmark V3.0 5.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_network_acl_allow_unrestricted_rdp_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.10] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Remote Desktop Protocol (RDP) protocol"""
    protocolPort = 3389
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for nacl in describe_network_acls(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(nacl,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        naclId = nacl["NetworkAclId"]
        naclArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:network-acl/{naclId}"
        # Evaluate the rules within the NACL - this check will fail on either IPv4 or IPv6 with only the specified protocol
        # as the default rules within a NACL are the "last place" DENY ALL and "first place" ALLOW ALL
        # this is only for CIS Benchmarking, as using NACLs is not considered best practice anymore, depending on what you're doing
        unrestrictedAccess = False
        for entry in nacl["Entries"]:
            egress = entry.get("Egress", False)
            ipV4CidrBlock = entry.get("CidrBlock")
            ipV6CidrBlock = entry.get("Ipv6CidrBlock")
            portRange = entry.get("PortRange", {})
            fromPort = portRange.get("From")
            toPort = portRange.get("To")
            # Override Bool if any IPv4 or IPv6 allows ingress
            if (
                not egress
                and (
                    ipV4CidrBlock == "0.0.0.0/0"
                    or ipV6CidrBlock == "::/0"
                )
                and (fromPort == protocolPort)
                and (toPort == protocolPort)
            ):
                unrestrictedAccess = True
                break
        # this is a failing finding
        if unrestrictedAccess is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{naclArn}/network-acl-allows-unrestricted-rdp-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{naclArn}/network-acl-allows-unrestricted-rdp-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.10] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Remote Desktop Protocol (RDP) protocol",
                "Description": f"Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) {naclId} allows unrestricted ingress to RDP (TCP Port 3389) to either IPv4 or IPv6 public CIDRs. A network access control list (ACL) allows or denies specific inbound or outbound traffic at the subnet level. You can use the default network ACL for your VPC, or you can create a custom network ACL for your VPC with rules that are similar to the rules for your security groups in order to add an additional layer of security to your VPC. You can create a custom network ACL and associate it with a subnet to allow or deny specific inbound or outbound traffic at the subnet level. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring NACLs for your Subnets refer to the Control traffic to subnets using network ACLs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-ephemeral-ports"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Access Control List"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkAcl",
                        "Id": naclArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkAcl": {
                                "NetworkAclId": naclId,
                                "VpcId": nacl["VpcId"],
                                "OwnerId": nacl["OwnerId"],
                                "Entries": nacl["Entries"]
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
                        "CIS Amazon Web Services Foundations Benchmark V1.5 5.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{naclArn}/network-acl-allows-unrestricted-rdp-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{naclArn}/network-acl-allows-unrestricted-rdp-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.10] Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) should not allowed unrestricted access to the Remote Desktop Protocol (RDP) protocol",
                "Description": f"Amazon Virtual Private Cloud (VPC) network access control lists (NACLs) {naclId} does not allow unrestricted ingress to RDP (TCP Port 3389) to either IPv4 or IPv6 public CIDRs.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring NACLs for your Subnets refer to the Control traffic to subnets using network ACLs section of the Amazon Virtual Private Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-ephemeral-ports"
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
                    "AssetService": "Amazon Virtual Private Cloud",
                    "AssetComponent": "Network Access Control List"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2NetworkAcl",
                        "Id": naclArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2NetworkAcl": {
                                "NetworkAclId": naclId,
                                "VpcId": nacl["VpcId"],
                                "OwnerId": nacl["OwnerId"],
                                "Entries": nacl["Entries"]
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
                        "CIS Amazon Web Services Foundations Benchmark V1.5 5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_privatelink_endpoint_unrestricted_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[VPC.11] AWS PrivateLink endpoints should not allow unrestricted access"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for endpoint in describe_vpc_endpoints(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(endpoint,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        endpointId = endpoint["VpcEndpointId"]
        endpointArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpc-endpoint/{endpointId}"
        serviceName = endpoint["ServiceName"]
        # Evaluate the Policy - if at least one of Action, Principal or Resource is NOT an asterisk (*)
        # OR if they are but a Condition is present, then this boolean will be overriden
        policyPassing = True
        if endpoint.get("PolicyDocument"):
            for statement in json.loads(endpoint.get("PolicyDocument")).get("Statement", []):
                # Break the loop if the VPC Endpoint doesn't support a policy - that's considered a Pass
                if serviceName not in check_vpc_endpoint_policy_support(cache, session):
                    break
                if (
                    statement.get("Action") == "*"
                    and statement.get("Principal") == "*"
                    and statement.get("Resource") == "*"
                    and "Condition" not in statement
                ):
                    policyPassing = False
                    break
        # this is a failing check
        if policyPassing is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{endpointArn}/vpc-endpoint-unrestricted-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{endpointArn}/vpc-endpoint-unrestricted-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[VPC.11] AWS PrivateLink endpoints should not allow unrestricted access",
                "Description": f"AWS PrivateLink endpoint {endpointId} for service {serviceName} does allow unrestricted acces. AWS PrivateLink is a highly available, scalable technology that you can use to privately connect your VPC to services as if they were in your VPC. You do not need to use an internet gateway, NAT device, public IP address, AWS Direct Connect connection, or AWS Site-to-Site VPN connection to allow communication with the service from your private subnets. Therefore, you control the specific API endpoints, sites, and services that are reachable from your VPC. An endpoint policy is a resource-based policy that you attach to a VPC endpoint to control which AWS principals can use the endpoint to access an AWS service. An endpoint policy does not override or replace identity-based policies or resource-based policies. For example, if you're using an interface endpoint to connect to Amazon S3, you can also use Amazon S3 bucket policies to control access to buckets from specific endpoints or specific VPCs. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud AWS PrivateLink Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html"
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
                    "AssetService": "AWS PrivateLink",
                    "AssetComponent": "VPC Endpoint"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpcEndpoint",
                        "Id": endpointArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "VpcEndpointId": endpointId,
                                "ServiceName": serviceName
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{endpointArn}/vpc-endpoint-unrestricted-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{endpointArn}/vpc-endpoint-unrestricted-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[VPC.11] AWS PrivateLink endpoints should not allow unrestricted access",
                "Description": f"AWS PrivateLink endpoint {endpointId} for service {serviceName} does not allow unrestricted access or the service does not support Endpoint Policies.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the default VPC refer to the Deleting Your Default Subnets and Default VPC section of the Amazon Virtual Private Cloud AWS PrivateLink Guide",
                        "Url": "https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html"
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
                    "AssetService": "AWS PrivateLink",
                    "AssetComponent": "VPC Endpoint"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpcEndpoint",
                        "Id": endpointArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "VpcEndpointId": endpointId,
                                "ServiceName": serviceName
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

## EOF?