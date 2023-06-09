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
import base64
import json

registry = CheckRegister()

def describe_vgws(cache, session):
    response = cache.get("describe_vgws")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_vgws"] = ec2.describe_vpn_gateways(DryRun=False, Filters=[{'Name': 'state','Values': ['available']}])["VpnGateways"]
    return cache["describe_vgws"]

def describe_cgws(cache, session):
    response = cache.get("describe_cgws")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_cgws"] = ec2.describe_customer_gateways(DryRun=False, Filters=[{'Name': 'state','Values': ['available']}])["CustomerGateways"]
    return cache["describe_cgws"]

def describe_s2s_vpns(cache, session):
    response = cache.get("describe_s2s_vpns")
    
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_s2s_vpns"] = ec2.describe_vpn_connections(DryRun=False, Filters=[{'Name': 'state','Values': ['available']}])["VpnConnections"]
    return cache["describe_s2s_vpns"]

@registry.register_check("ec2")
def aws_vgw_attached_to_vpc_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.1] Amazon Virtual Private Gateways should be associated with a VPC"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vgw in describe_vgws(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vgw,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        gatewayId = vgw["VpnGatewayId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpn-gateway/{gatewayId}"
        # This is a failing check
        if not vgw["VpcAttachments"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-vgw-attached-to-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-vgw-attached-to-vpc-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S2SVPN.1] Amazon Virtual Private Gateways should be associated with a VPC",
                "Description": f"Amazon Virtual Private Gateway (VGW) {gatewayId} is not associated with a VPC. To establish a VPN connection between your VPC and your on-premises network, you must create a target gateway on the AWS side of the connection. The target gateway can be a virtual private gateway or a transit gateway. A virtual private gateway is the VPN concentrator on the Amazon side of the Site-to-Site VPN connection. You create a virtual private gateway and attach it to a virtual private cloud (VPC) with resources that must access the Site-to-Site VPN connection. Without a targeted VPC, any Site-to-Site VPNs associated with your VGW will always have their tunnels in a DOWN state which will cause a loss of availability. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on VGWs and how to manage them refer to the Virtual private gateway section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/how_it_works.html#VPNGateway"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "Virtual Private Gateway"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnGateway",
                        "Id": gatewayArn,
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
                "Id": f"{gatewayArn}/aws-eni-attached-in-use-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-eni-attached-in-use-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.1] Amazon Virtual Private Gateways should be associated with a VPC",
                "Description": f"Amazon Virtual Private Gateway (VGW) {gatewayId} is associated with a VPC.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on VGWs and how to manage them refer to the Virtual private gateway section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/how_it_works.html#VPNGateway"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "Virtual Private Gateway"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnGateway",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
def aws_cgw_certificate_authn_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.2] Consider using an AWS ACM Certificate for mutual authentication with Amazon Customer Gateways"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for cgw in describe_cgws(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(cgw,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        gatewayId = cgw["CustomerGatewayId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:customer-gateway/{gatewayId}"
        
        # This is a failing check
        if "CertificateArn" not in cgw:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-cgw-acm-authn-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-cgw-acm-authn-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S2SVPN.2] Consider using an AWS ACM Certificate for mutual authentication with Amazon Customer Gateways",
                "Description": f"Amazon Customer Gateway (CGW) {gatewayId} does not use mutual authentication with Amazon Certificate Manager. A customer gateway is a resource that you create in AWS that represents the customer gateway device in your on-premises network. When you create a customer gateway, you provide information about your device to AWS. To use Amazon VPC with a Site-to-Site VPN connection, you or your network administrator must also configure the customer gateway device or application in your remote network. If you want to use certificate based authentication, provide the ARN of an ACM private certificate that will be used on your customer gateway device. When you create a customer gateway, you can configure the customer gateway to use AWS Private Certificate Authority private certificates to authenticate the Site-to-Site VPN. When you choose to use this option, you create an entirely AWS-hosted private certificate authority (CA) for internal use by your organization. Both the root CA certificate and subordinate CA certificates are stored and managed by AWS Private CA. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on configuring ACM-PCA for your CGWs refer to the Customer gateway options for your Site-to-Site VPN connection section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/cgw-options.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "Customer Gateway"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2CustomerGateway",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
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
                "Id": f"{gatewayArn}/aws-cgw-acm-authn-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-cgw-acm-authn-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.2] Consider using an AWS ACM Certificate for mutual authentication with Amazon Customer Gateways",
                "Description": f"Amazon Customer Gateway (CGW) {gatewayId} does use mutual authentication with Amazon Certificate Manager.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on configuring ACM-PCA for your CGWs refer to the Customer gateway options for your Site-to-Site VPN connection section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/cgw-options.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "Customer Gateway"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2CustomerGateway",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_s2s_vpn_connection_two_active_tunnels_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.3] Amazon Site-to-Site VPNs (S2S VPN) should have two active tunnels"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpnconn in describe_s2s_vpns(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpnconn,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpnConnectionId = vpnconn["VpnConnectionId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpn-connection/{vpnConnectionId}"
        # Use a list comprehension to create a list of STATUS that we can check for "DOWN"
        tunnelStatus = [tunnel["Status"] for tunnel in vpnconn["VgwTelemetry"]]
        # This is a failing check
        if "DOWN" in tunnelStatus:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-two-active-tunnels-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-two-active-tunnels-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[S2SVPN.3] Amazon Site-to-Site VPNs (S2S VPN) should have two active tunnels",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} has one or more tunnels that are in a 'DOWN' state. Monitoring is an important part of maintaining the reliability, availability, and performance of your AWS Site-to-Site VPN connection. You should collect monitoring data from all of the parts of your solution so that you can more easily debug a multi-point failure if one occurs. When one of your tunnels are down services can be impacted, both tunnels being down will cause your VPN to fail and result in an outage. Ensure you are continually monitoring your VPN using AWS Health, CloudWatch Alarms, VPN Logging and other mechanisms in your on-premise environment. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN health monitoring refer to the Monitoring your Site-to-Site VPN connection section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/monitoring-overview-vpn.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-two-active-tunnels-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-two-active-tunnels-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.3] Amazon Site-to-Site VPNs (S2S VPN) should have two active tunnels",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} has both tunnels in a 'UP' state.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN health monitoring refer to the Monitoring your Site-to-Site VPN connection section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/monitoring-overview-vpn.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_s2s_vpn_connection_tunnel_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.4] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have logging enabled"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpnconn in describe_s2s_vpns(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpnconn,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpnConnectionId = vpnconn["VpnConnectionId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpn-connection/{vpnConnectionId}"
        # Use a list comprehension to create a list of LogEnabled that we can check for False
        tunnelLogging = [tunnel["LogOptions"]["CloudWatchLogOptions"]["LogEnabled"] for tunnel in vpnconn["Options"]["TunnelOptions"]]
        # This is a failing check
        if False in tunnelLogging:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-tunnel-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-tunnel-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S2SVPN.4] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have logging enabled",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} has one or more tunnels that do not have logging enabled. AWS Site-to-Site VPN logs provide you with deeper visibility into your Site-to-Site VPN deployments. With this feature, you have access to Site-to-Site VPN connection logs that provide details on IP Security (IPsec) tunnel establishment, Internet Key Exchange (IKE) negotiations, and dead peer detection (DPD) protocol messages. Site-to-Site VPN logs can be published to Amazon CloudWatch Logs. This feature provides customers with a single consistent way to access and analyze detailed logs for all of their Site-to-Site VPN connections. Site-to-Site VPN logs help you to pinpoint configuration mismatches between AWS and your customer gateway device, and address initial VPN connectivity issues. VPN connections can intermittently flap over time due to misconfigured settings (such as poorly tuned timeouts), there can be issues in the underlying transport networks (like internet weather), or routing changes or path failures can cause disruption of connectivity over VPN. This feature allows you to accurately diagnose the cause of intermittent connection failures and fine-tune low-level tunnel configuration for reliable operation. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN logging refer to the AWS Site-to-Site VPN logs section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/monitoring-logs.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
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
                "Id": f"{gatewayArn}/aws-s2s-vpn-tunnel-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-tunnel-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.4] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have logging enabled",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} has logging enabled on all tunnels.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN logging refer to the AWS Site-to-Site VPN logs section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/monitoring-logs.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
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
def aws_s2s_vpn_connection_tunnel_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.5] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have lifecycle control enabled"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpnconn in describe_s2s_vpns(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpnconn,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpnConnectionId = vpnconn["VpnConnectionId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpn-connection/{vpnConnectionId}"
        # Use a list comprehension to create a list of LogEnabled that we can check for False
        lifecyclePolicy = [tunnel["EnableTunnelLifecycleControl"] for tunnel in vpnconn["Options"]["TunnelOptions"]]
        # This is a failing check
        if False in lifecyclePolicy:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-tunnel-endpoint-lifecycle-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-tunnel-endpoint-lifecycle-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S2SVPN.5] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have lifecycle control enabled",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} has one or more tunnels that do not have lifecycle control enabled. Tunnel endpoint lifecycle control provides control over the schedule of endpoint replacements, and can help minimize connectivity disruptions during AWS managed tunnel endpoint replacements. With this feature, you can choose to accept AWS managed updates to tunnel endpoints at a time that works best for your business. Use this feature if you have short-term business needs or can only support a single tunnel per VPN connection. Turn on the tunnel endpoint lifecycle control feature for individual tunnels within a VPN connection. It can be enabled at the time of VPN creation or by modifying tunnel options for an existing VPN connection. When a tunnel endpoint maintenance is available, you will have the opportunity to accept the update at a time that is convenient for you, before the given Maintenance auto applied after timestamp. In rare circumstances, AWS might apply critical updates to tunnel endpoints immediately, even if the tunnel endpoint lifecycle control feature is enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN tunnel endpoint lifecycle control refer to the Tunnel endpoint lifecycle control section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-endpoint-lifecycle.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-tunnel-endpoint-lifecycle-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-tunnel-endpoint-lifecycle-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.5] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have lifecycle control enabled",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} lifecycle control enabled for all tunnels.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN tunnel endpoint lifecycle control refer to the Tunnel endpoint lifecycle control section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-endpoint-lifecycle.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_s2s_vpn_connection_tgw_acceleration_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.6] Amazon Site-to-Site VPNs (S2S VPN) connections attached to Transit Gateways should enable acceleration"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vpnconn in describe_s2s_vpns(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vpnconn,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        vpnConnectionId = vpnconn["VpnConnectionId"]
        gatewayArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:vpn-connection/{vpnConnectionId}"
        # First, check if the VPN is associated with a TGW, and if it is check if acceleration is enabled
        if "TransitGatewayId" not in vpnconn:
            accelerationFailed = False
        else:
            if vpnconn["Options"]["EnableAcceleration"] is False:
                accelerationFailed = True
            else:
                accelerationFailed = False

        # This is a failing check
        if accelerationFailed is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gatewayArn}/aws-s2s-vpn-with-tgw-acceleration-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-with-tgw-acceleration-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S2SVPN.6] Amazon Site-to-Site VPNs (S2S VPN) connections attached to Transit Gateways should enable acceleration",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} is associated with a Transit Gateway and does not enable acceleration. You can optionally enable acceleration for your Site-to-Site VPN connection. An accelerated Site-to-Site VPN connection (accelerated VPN connection) uses AWS Global Accelerator to route traffic from your on-premises network to an AWS edge location that is closest to your customer gateway device. AWS Global Accelerator optimizes the network path, using the congestion-free AWS global network to route traffic to the endpoint that provides the best application performance. You can use an accelerated VPN connection to avoid network disruptions that might occur when traffic is routed over the public internet. By default, when you create a Site-to-Site VPN connection, acceleration is disabled. You can optionally enable acceleration when you create a new Site-to-Site VPN attachment on a transit gateway. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN acceleration refer to the Accelerated Site-to-Site VPN connections section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/accelerated-vpn.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
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
                "Id": f"{gatewayArn}/aws-s2s-vpn-with-tgw-acceleration-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gatewayArn}/aws-s2s-vpn-with-tgw-acceleration-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S2SVPN.6] Amazon Site-to-Site VPNs (S2S VPN) connections attached to Transit Gateways should enable acceleration",
                "Description": f"Amazon Site-to-Site VPN Connection {vpnConnectionId} is either not associated with a Transit Gateway (and thus cannot be accelerated) or it is associated with a Transit Gateway and has acceleration enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on S2S VPN acceleration refer to the Accelerated Site-to-Site VPN connections section of the AWS Site-to-Site VPN User Guide",
                        "Url": "https://docs.aws.amazon.com/vpn/latest/s2svpn/accelerated-vpn.html"
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
                    "AssetService": "AWS Site-to-Site VPN",
                    "AssetComponent": "VPN Connection"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2VpnConnection",
                        "Id": gatewayArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "VpnConnectionId": vpnConnectionId,
                            "Options": vpnconn["Options"]
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