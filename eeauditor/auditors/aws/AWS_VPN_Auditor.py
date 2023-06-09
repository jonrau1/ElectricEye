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

    cache["describe_vgws"] = ec2.describe_vpn_gateways(DryRun=False)["VpnGateways"]
    return cache["describe_vgws"]

@registry.register_check("ec2")
def aws_vgw_attached_to_vpc_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S2SVPN.1] Amazon Virtual Private Gateways should be associated with a VPC"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for vgw in describe_vgws(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(vgw,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        gatewayId = vgw["VerifiedAccessInstanceId"]
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
                "Title": "[VPC.9] Amazon Virtual Private Gateways should be associated with a VPC",
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
                "Title": "[VPC.9] Amazon Virtual Private Gateways should be associated with a VPC",
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

# [S2SVPN.2] Consider using an AWS ACM Certificate for mutual authentication with Amazon Customer Gateways

# [S2SVPN.3] Amazon Site-to-Site VPNs (S2S VPN) should have two active tunnels

# [S2SVPN.4] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have logging enabled

# [S2SVPN.5] Amazon Site-to-Site VPNs (S2S VPN) tunnels should have enhanced maintainence controls enabled