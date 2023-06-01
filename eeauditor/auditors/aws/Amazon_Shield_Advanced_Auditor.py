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
from botocore.exceptions import ClientError
import base64
import json

registry = CheckRegister()

@registry.register_check("shield")
def shield_advanced_route_53_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.1] Route 53 Hosted Zones should be protected by Shield Advanced"""
    route53 = session.client("route53")
    shield = session.client("shield", region_name="us-east-1")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = route53.list_hosted_zones()
    for hostedzone in response["HostedZones"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(hostedzone,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        rawHzId = str(hostedzone["Id"])
        hostedZoneId = rawHzId.replace("/hostedzone/", "")
        hostedZoneArn = f"arn:{awsPartition}:route53:::hostedzone/{hostedZoneId}"
        protectionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection/{hostedZoneArn}"
        try:
            # this is a passing check
            shield.describe_protection(ResourceArn=hostedZoneArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/route53-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/route53-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.1] Route 53 Hosted Zones should be protected by Shield Advanced",
                "Description": f"Route53 Hosted Zone {hostedZoneId} is protected by Shield Advanced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "Amazon Route53",
                    "AssetComponent": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hostedZoneArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"hostedZoneId": hostedZoneId}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except ClientError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/route53-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/route53-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.1] Route 53 Hosted Zones should be protected by Shield Advanced",
                "Description": f"Route53 Hosted Zone {hostedZoneId} is not protected by Shield Advanced. AWS Shield Advanced is a managed service that helps you protect your application against external threats, like DDoS attacks, volumetric bots, and vulnerability exploitation attempts. For higher levels of protection against attacks, you can subscribe to AWS Shield Advanced. When you subscribe to Shield Advanced and add protection to your resources, Shield Advanced provides expanded DDoS attack protection for those resources. The protections that you receive from Shield Advanced can vary depending on your architecture and configuration choices. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "Amazon Route53",
                    "AssetComponent": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hostedZoneArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"hostedZoneId": hostedZoneId}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_elb_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.2] Classic Load Balancers should be protected by Shield Advanced"""
    shield = session.client("shield", region_name="us-east-1")
    elbclassic = session.client("elb")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for classicbalancer in elbclassic.describe_load_balancers()["LoadBalancerDescriptions"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(classicbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = f"arn:{awsPartition}:elasticloadbalancing:{awsRegion}:{awsAccountId}:loadbalancer/{clbName}"
        protectionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection/{clbArn}"
        try:
            # this is a passing check
            shield.describe_protection(ResourceArn=clbArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/classiclb-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/classiclb-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.2] Classic Load Balancers should be protected by Shield Advanced",
                "Description": f"Classic Load Balancer {clbName} is protected by Shield Advanced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "AWS Elastic Load Balancer",
                    "AssetComponent": "Classic Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except ClientError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/classiclb-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/classiclb-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.2] Classic Load Balancers should be protected by Shield Advanced",
                "Description": f"Classic Load Balancer {clbName} is not protected by Shield Advanced. AWS Shield Advanced is a managed service that helps you protect your application against external threats, like DDoS attacks, volumetric bots, and vulnerability exploitation attempts. For higher levels of protection against attacks, you can subscribe to AWS Shield Advanced. When you subscribe to Shield Advanced and add protection to your resources, Shield Advanced provides expanded DDoS attack protection for those resources. The protections that you receive from Shield Advanced can vary depending on your architecture and configuration choices. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                    "AssetService": "AWS Elastic Load Balancer",
                    "AssetComponent": "Classic Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_elb_v2_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.3] Application Load Balancers should be protected by Shield Advanced"""
    shield = session.client("shield", region_name="us-east-1")
    elbv2 = session.client("elbv2")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for loadbalancer in elbv2.describe_load_balancers()["LoadBalancers"]:
        # Skip NLBs
        elbv2LbType = str(loadbalancer["Type"])
        if elbv2LbType == "network":
            continue

        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Name = str(loadbalancer["LoadBalancerName"])
        elbv2Arn = str(loadbalancer["LoadBalancerArn"])
        protectionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection/{elbv2Arn}"
        elbv2DnsName = str(loadbalancer["DNSName"])
        elbv2Scheme = str(loadbalancer["Scheme"])
        elbv2VpcId = str(loadbalancer["VpcId"])
        elbv2IpAddressType = str(loadbalancer["IpAddressType"])
        try:
            # this is a passing check
            shield.describe_protection(ResourceArn=elbv2Arn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/elbv2-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/elbv2-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.3] Application Load Balancers should be protected by Shield Advanced",
                "Description": f"Application Load Balancer {elbv2Name} is protected by Shield Advanced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "AWS Elastic Load Balancer V2",
                    "AssetComponent": "Application Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "AwsElbv2LoadBalancer",
                        "Id": elbv2Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElbv2LoadBalancer": {
                                "DNSName": elbv2DnsName,
                                "IpAddressType": elbv2IpAddressType,
                                "Scheme": elbv2Scheme,
                                "Type": elbv2LbType,
                                "VpcId": elbv2VpcId,
                            }
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except ClientError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/elbv2-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/elbv2-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.3] Application Load Balancers should be protected by Shield Advanced",
                "Description": f"Application Load Balancer {elbv2Name} is not protected by Shield Advanced. AWS Shield Advanced is a managed service that helps you protect your application against external threats, like DDoS attacks, volumetric bots, and vulnerability exploitation attempts. For higher levels of protection against attacks, you can subscribe to AWS Shield Advanced. When you subscribe to Shield Advanced and add protection to your resources, Shield Advanced provides expanded DDoS attack protection for those resources. The protections that you receive from Shield Advanced can vary depending on your architecture and configuration choices. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                    "AssetService": "AWS Elastic Load Balancer V2",
                    "AssetComponent": "Application Load Balancer"
                },
                "Resources": [
                    {
                        "Type": "AwsElbv2LoadBalancer",
                        "Id": elbv2Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsElbv2LoadBalancer": {
                                "DNSName": elbv2DnsName,
                                "IpAddressType": elbv2IpAddressType,
                                "Scheme": elbv2Scheme,
                                "Type": elbv2LbType,
                                "VpcId": elbv2VpcId,
                            }
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_eip_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.4] Elastic IPs should be protected by Shield Advanced"""
    shield = session.client("shield", region_name="us-east-1")
    ec2 = session.client("ec2")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for elasticip in ec2.describe_addresses()["Addresses"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(elasticip,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        allocationId = str(elasticip["AllocationId"])
        eipAllocationArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:eip-allocation/{allocationId}"
        protectionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection/{eipAllocationArn}"
        try:
            # this is a passing check
            shield.describe_protection(ResourceArn=eipAllocationArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/elasticip-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/elasticip-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.4] Elastic IPs should be protected by Shield Advanced",
                "Description": f"Elastic IP allocation {allocationId} is protected by Shield Advanced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Elastic IP"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipAllocationArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"AllocationId": allocationId}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except ClientError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/elasticip-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/elasticip-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.4] Elastic IPs should be protected by Shield Advanced",
                "Description": f"Elastic IP allocation {allocationId} is not protected by Shield Advanced. AWS Shield Advanced is a managed service that helps you protect your application against external threats, like DDoS attacks, volumetric bots, and vulnerability exploitation attempts. For higher levels of protection against attacks, you can subscribe to AWS Shield Advanced. When you subscribe to Shield Advanced and add protection to your resources, Shield Advanced provides expanded DDoS attack protection for those resources. The protections that you receive from Shield Advanced can vary depending on your architecture and configuration choices. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Elastic IP"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipAllocationArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"AllocationId": allocationId}},
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_cloudfront_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.5] CloudFront distributions should be protected by Shield Advanced"""
    shield = session.client("shield", region_name="us-east-1")
    cloudfront = session.client("cloudfront", region_name="us-east-1")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = cloudfront.list_distributions()
    cfDistros = response["DistributionList"].get("Items", [])
    for distro in cfDistros:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(distro,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distroId = str(distro["Id"])
        distroArn = str(distro["ARN"])
        protectionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection/{distroArn}"
        distroDomainName = str(distro["DomainName"])
        try:
            # this is a passing check
            shield.describe_protection(ResourceArn=distroArn)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/cloudfront-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/cloudfront-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.5] CloudFront distributions should be protected by Shield Advanced",
                "Description": f"CloudFront distribution {distroId} is protected by Shield Advanced.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distroArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {"DomainName": distroDomainName}
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except ClientError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{protectionArn}/cloudfront-shield-adv-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{protectionArn}/cloudfront-shield-adv-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.5] CloudFront distributions should be protected by Shield Advanced",
                "Description": f"CloudFront distribution {distroId} is not protected by Shield Advanced. AWS Shield Advanced is a managed service that helps you protect your application against external threats, like DDoS attacks, volumetric bots, and vulnerability exploitation attempts. For higher levels of protection against attacks, you can subscribe to AWS Shield Advanced. When you subscribe to Shield Advanced and add protection to your resources, Shield Advanced provides expanded DDoS attack protection for those resources. The protections that you receive from Shield Advanced can vary depending on your architecture and configuration choices. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on adding Shield Advanced protection to resources refer to the AWS Shield Advanced protected resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary-protected-resources.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distroArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {"DomainName": distroDomainName}
                        },
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
                        "ISO 27001:2013 A.17.2.1",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1498"
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_drt_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.6] The AWS Shield Response Team (SRT) should be authorized to take action in your account"""
    shield = session.client("shield")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

    srtArn = f"arn:{awsPartition}:shield::{awsAccountId}:srtaccess"
    
    try:
        response = shield.describe_drt_access()
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # this is a passing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{srtArn}/shield-adv-drt-iam-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{srtArn}/shield-adv-drt-iam-access-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.6] The AWS Shield Response Team (SRT) should be authorized to take action in your account",
            "Description": f"The AWS Shield Response Team (SRT) is authorized to take action in Account {awsAccountId}",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on authorizing the SRT to access your Account and the services they can provided refer to the Configuring access for the Shield Response Team (SRT) section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                    "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-srt-access.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Shield Response Team Access"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": srtArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-6",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AC-19",
                    "NIST SP 800-53 Rev. 4 AC-24",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 PE-2",
                    "NIST SP 800-53 Rev. 4 PS-3",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.7.1.1",
                    "ISO 27001:2013 A.9.2.1",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding
    except ClientError:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{srtArn}/shield-adv-drt-iam-access-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{srtArn}/shield-adv-drt-iam-access-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.6] The AWS Shield Response Team (SRT) should be authorized to take action in your account",
            "Description": f"The AWS Shield Response Team (SRT) is not authorized to take action in Account {awsAccountId}. You can grant permission to the Shield Response Team (SRT) to act on your behalf, accessing your AWS WAF logs and making calls to the AWS Shield Advanced and AWS WAF APIs to manage protections. During application layer DDoS events, the SRT can monitor AWS WAF requests to identify anomalous traffic and help craft custom AWS WAF rules to mitigate offending traffic sources. Additionally, you can grant the SRT access to other data that you have stored in Amazon S3 buckets, such as packet captures or logs from an Application Load Balancer, Amazon CloudFront, or from third party sources. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on authorizing the SRT to access your Account and the services they can provided refer to the Configuring access for the Shield Response Team (SRT) section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                    "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-srt-access.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": None,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Shield Response Team Access"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": srtArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-6",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AC-19",
                    "NIST SP 800-53 Rev. 4 AC-24",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 PE-2",
                    "NIST SP 800-53 Rev. 4 PS-3",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.7.1.1",
                    "ISO 27001:2013 A.9.2.1",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding

@registry.register_check("shield")
def shield_advanced_subscription_autorenew_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.7] Shield Advanced subscription should be set to auto-renew"""
    subscriptionArn = f"arn:{awsPartition}:shield::{awsAccountId}:protection"

    shield = session.client("shield")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    try:
        response = shield.describe_subscription()
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        renewCheck = str(response["Subscription"]["AutoRenew"])
    except ClientError:
        renewCheck = "DISABLED"

    if renewCheck == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{subscriptionArn}/shield-adv-subscription-auto-renew-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{subscriptionArn}/shield-adv-subscription-auto-renew-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.7] Shield Advanced subscription should be set to auto-renew",
            "Description": f"The Shield Advanced subscription for {awsAccountId} is not set to auto-renew, or there is not an existing Subscription at all. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To update the subscription renewel use the UpdateSubscription API, refer to the link for more details.",
                    "Url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_UpdateSubscription.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": None,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Subscription"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": subscriptionArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.12.5.1",
                ],
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{subscriptionArn}/shield-adv-subscription-auto-renew-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{subscriptionArn}/shield-adv-subscription-auto-renew-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.7] Shield Advanced subscription should be set to auto-renew",
            "Description": f"The Shield Advanced subscription for {awsAccountId} is set to auto-renew.",
            "Remediation": {
                "Recommendation": {
                    "Text": "To update the subscription renewal use the UpdateSubscription API, refer to the link for more details.",
                    "Url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_UpdateSubscription.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Subscription"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": subscriptionArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.12.5.1",
                ],
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding

@registry.register_check("shield")
def shield_advanced_global_accelerator_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.8] Global Accelerator Accelerators should be protected by Shield Advanced"""
    shield = session.client("shield", region_name="us-east-1")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

    gax = session.client("globalaccelerator", region_name="us-west-2")
    paginator = gax.get_paginator("list_accelerators")
    iterator = paginator.paginate()
    for page in iterator:
        for ga in page["Accelerators"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(ga,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            gaxArn = str(ga["AcceleratorArn"])
            gaxName = str(ga["Name"])
            gaxDns = str(ga["DnsName"])
            iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
            try:
                # this is a passing check
                shield.describe_protection(ResourceArn=gaxArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": gaxArn + "/global-accelerator-shield-adv-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": gaxArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ShieldAdvanced.8] Global Accelerator Accelerators should be protected by Shield Advanced",
                    "Description": "Global Accelerator "
                    + gaxName
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                        "AssetService": "Amazon Global Accelerator",
                        "AssetComponent": "Accelerator"
                    },
                    "Resources": [
                        {
                            "Type": "AwsGlobalAcceleratorAccelerator",
                            "Id": gaxArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "Name": gaxName,
                                    "DnsName": gaxDns
                                }
                            }
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
                            "ISO 27001:2013 A.17.2.1",
                            "MITRE ATT&CK T1595",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1498"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            except Exception as e:
                if str(e) == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist.":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": gaxArn + "/global-accelerator-shield-adv-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": gaxArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.8] Global Accelerator Accelerators should be protected by Shield Advanced",
                        "Description": "Global Accelerator "
                        + gaxName
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                            "AssetService": "Amazon Global Accelerator",
                            "AssetComponent": "Accelerator"
                        },
                        "Resources": [
                            {
                                "Type": "AwsGlobalAcceleratorAccelerator",
                                "Id": gaxArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "Name": gaxName,
                                        "DnsName": gaxDns
                                    }
                                }
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
                                "ISO 27001:2013 A.17.2.1",
                                "MITRE ATT&CK T1595",
                                "MITRE ATT&CK T1590",
                                "MITRE ATT&CK T1498"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding

@registry.register_check("shield")
def shield_advanced_subscription_latest_attacks(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ShieldAdvanced.9] AWS Shield resources under attack in the last two weeks should be investigated"""
    shield = session.client("shield", region_name="us-east-1")
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    response = shield.list_attacks(
        StartTime = {
            'FromInclusive': datetime.datetime.utcnow() - datetime.timedelta(days=14)
        },
        EndTime = {
            'ToExclusive': datetime.datetime.utcnow()
        }
    )
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(response,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    # this is a passing check
    if not response['AttackSummaries']:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + "/shield-adv-subscription-latest-attacks",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.9] AWS Shield resources under attack in the last two weeks should be investigated",
            "Description": f"The resources in {awsAccountId} have not had an attack mitigated by AWS Shield Advanced in the last week",
            "Remediation": {
                "Recommendation": {
                    "Text": "View the docs for more details about how to ensure your AWS environments are protected against DDOS attacks.",
                    "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-manage-protected-resources.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Attack"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Shield_Advanced_Attacks",
                    "Partition": awsPartition,
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.12.5.1",
                    "MITRE ATT&CK T1595",
                    "MITRE ATT&CK T1590",
                    "MITRE ATT&CK T1498"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    # this is a failing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": awsAccountId + "/shield-adv-subscription-latest-attacks",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[ShieldAdvanced.9] AWS Shield resources under attack in the last two weeks should be investigated",
            "Description": f"The resources in {awsAccountId} have had at least one attack mitigated by AWS Shield Advanced in the last week",
            "Remediation": {
                "Recommendation": {
                    "Text": "View the docs for more details about how to ensure your AWS environments are protected against DDOS attacks.",
                    "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/ddos-manage-protected-resources.html",
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Shield Advanced",
                "AssetComponent": "Attack"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                    "Partition": awsPartition,
                    "Region": awsRegion,
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
                    "ISO 27001:2013 A.12.5.1",
                    "MITRE ATT&CK T1595",
                    "MITRE ATT&CK T1590",
                    "MITRE ATT&CK T1498"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding