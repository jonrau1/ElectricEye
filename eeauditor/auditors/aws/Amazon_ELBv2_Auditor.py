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

import tomli
import os
import sys
import boto3
import requests
import ipaddress
import datetime
from botocore.exceptions import ClientError
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def describe_load_balancers(cache, session):
    response = cache.get("describe_load_balancers")
    if response:
        return response
    
    elbv2 = session.client("elbv2")

    cache["describe_load_balancers"] = elbv2.describe_load_balancers()["LoadBalancers"]
    return cache["describe_load_balancers"]

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def get_shodan_api_key(cache):

    response = cache.get("get_shodan_api_key")
    if response:
        return response

    validCredLocations = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

    # Get the absolute path of the current directory
    currentDir = os.path.abspath(os.path.dirname(__file__))
    # Go two directories back to /eeauditor/
    twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

    # TOML is located in /eeauditor/ directory
    tomlFile = f"{twoBack}/external_providers.toml"
    with open(tomlFile, "rb") as f:
        data = tomli.load(f)

    # Parse from [global] to determine credential location of PostgreSQL Password
    credLocation = data["global"]["credentials_location"]
    shodanCredValue = data["global"]["shodan_api_key_value"]
    if credLocation not in validCredLocations:
        print(f"Invalid option for [global.credLocation]. Must be one of {str(validCredLocations)}.")
        sys.exit(2)
    if not shodanCredValue:
        apiKey = None
    else:

        # Boto3 Clients
        ssm = boto3.client("ssm")
        asm = boto3.client("secretsmanager")

        # Retrieve API Key
        if credLocation == "CONFIG_FILE":
            apiKey = shodanCredValue

        # Retrieve the credential from SSM Parameter Store
        elif credLocation == "AWS_SSM":
            
            try:
                apiKey = ssm.get_parameter(
                    Name=shodanCredValue,
                    WithDecryption=True
                )["Parameter"]["Value"]
            except ClientError as e:
                print(f"Error retrieving API Key from SSM, skipping all Shodan checks, error: {e}")
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as e:
                print(f"Error retrieving API Key from ASM, skipping all Shodan checks, error: {e}")
                apiKey = None
        
    cache["get_shodan_api_key"] = apiKey
    return cache["get_shodan_api_key"]

def google_dns_resolver(target):
    """
    Accepts a Public DNS name and attempts to use Google's DNS A record resolver to determine an IP address
    """
    url = f"https://dns.google/resolve?name={target}&type=A"
    
    r = requests.get(url=url)
    if r.status_code != 200:
        return None
    else:
        for result in json.loads(r.text)["Answer"]:
            try:
                if not (
                    ipaddress.IPv4Address(result["data"]).is_private
                    or ipaddress.IPv4Address(result["data"]).is_loopback
                    or ipaddress.IPv4Address(result["data"]).is_link_local
                ):
                    return result["data"]
                else:
                    continue
            except ipaddress.AddressValueError:
                continue
        # if the loop terminates without any result return None
        return None

@registry.register_check("elasticloadbalancingv2")
def elbv2_alb_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.1] Application Load Balancers should have access logging enabled"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        if elbv2LbType == "application":
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response["Attributes"]
            for attributes in elbv2Attributes:
                if str(attributes["Key"]) == "access_logs.s3.enabled":
                    elbv2LoggingCheck = str(attributes["Value"])
                    if elbv2LoggingCheck == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ELBv2.1] Application Load Balancers should have access logging enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + " does not have access logging enabled. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
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
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.1] Application and Network Load Balancers should have access logging enabled",
                            "Description": "ELB "
                            + elbv2LbType
                            + " load balancer "
                            + elbv2Name
                            + " has access logging enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
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
                                        },
                                    },
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
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                else:
                    continue
        else:
            continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_deletion_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        if elbv2LbType == "application":
            eeAssetType = "Application Load Balancer"
        else:
            eeAssetType = "Network Load Balancer"
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response["Attributes"]
        for attributes in elbv2Attributes:
            if str(attributes["Key"]) == "deletion_protection.enabled":
                elbv2LoggingCheck = str(attributes["Value"])
                if elbv2LoggingCheck == "false":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-deletion-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " does not have deletion protection enabled. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection",
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
                            "AssetComponent": eeAssetType
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
                                    },
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.IP-3",
                                "NIST CSF V1.1 PR.PT-5",
                                "NIST SP 800-53 Rev. 4 AU-4",
                                "NIST SP 800-53 Rev. 4 CM-3",
                                "NIST SP 800-53 Rev. 4 CM-4",
                                "NIST SP 800-53 Rev. 4 CP-2",
                                "NIST SP 800-53 Rev. 4 CP-7",
                                "NIST SP 800-53 Rev. 4 CP-8",
                                "NIST SP 800-53 Rev. 4 CP-11",
                                "NIST SP 800-53 Rev. 4 CP-13",
                                "NIST SP 800-53 Rev. 4 PL-8",
                                "NIST SP 800-53 Rev. 4 SA-10",
                                "NIST SP 800-53 Rev. 4 SA-14",
                                "NIST SP 800-53 Rev. 4 SC-5",
                                "NIST SP 800-53 Rev. 4 SC-6",
                                "AICPA TSC CC8.1",
                                "AICPA TSC A1.2",
                                "ISO 27001:2013 A.12.1.2",
                                "ISO 27001:2013 A.12.5.1",
                                "ISO 27001:2013 A.12.6.2",
                                "ISO 27001:2013 A.14.2.2",
                                "ISO 27001:2013 A.14.2.3",
                                "ISO 27001:2013 A.14.2.4",
                                "ISO 27001:2013 A.17.1.2",
                                "ISO 27001:2013 A.17.2.1"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-deletion-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " has deletion protection enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection",
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
                            "AssetComponent": eeAssetType
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
                                    },
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.IP-3",
                                "NIST CSF V1.1 PR.PT-5",
                                "NIST SP 800-53 Rev. 4 AU-4",
                                "NIST SP 800-53 Rev. 4 CM-3",
                                "NIST SP 800-53 Rev. 4 CM-4",
                                "NIST SP 800-53 Rev. 4 CP-2",
                                "NIST SP 800-53 Rev. 4 CP-7",
                                "NIST SP 800-53 Rev. 4 CP-8",
                                "NIST SP 800-53 Rev. 4 CP-11",
                                "NIST SP 800-53 Rev. 4 CP-13",
                                "NIST SP 800-53 Rev. 4 PL-8",
                                "NIST SP 800-53 Rev. 4 SA-10",
                                "NIST SP 800-53 Rev. 4 SA-14",
                                "NIST SP 800-53 Rev. 4 SC-5",
                                "NIST SP 800-53 Rev. 4 SC-6",
                                "AICPA TSC CC8.1",
                                "AICPA TSC A1.2",
                                "ISO 27001:2013 A.12.1.2",
                                "ISO 27001:2013 A.12.5.1",
                                "ISO 27001:2013 A.12.6.2",
                                "ISO 27001:2013 A.14.2.2",
                                "ISO 27001:2013 A.14.2.3",
                                "ISO 27001:2013 A.14.2.4",
                                "ISO 27001:2013 A.17.1.2",
                                "ISO 27001:2013 A.17.2.1"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            else:
                continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_internet_facing_secure_listeners_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        if elbv2LbType == "application":
            eeAssetType = "Application Load Balancer"
        else:
            eeAssetType = "Network Load Balancer"
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
        myElbv2Listeners = response["Listeners"]
        for listeners in myElbv2Listeners:
            listenerProtocol = str(listeners["Protocol"])
            if (elbv2Scheme == "internet-facing" 
                and listenerProtocol != "HTTPS" or "TLS"
            ):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": elbv2Arn + "/internet-facing-secure-listeners-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured",
                    "Description": f"ELB {elbv2LbType} load balancer {elbv2Name} does not have a secure listener configured.  Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
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
                        "AssetComponent": eeAssetType
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
                                },
                            },
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
                    "Id": elbv2Arn + "/internet-facing-secure-listeners-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured",
                    "Description": f"ELB {elbv2LbType} load balancer {elbv2Name} does have a secure listener configured. Not using a secure listener (HTTPS/TLS) can lead to adversaries performing Man-in-the-Middle (MITM) attacks, eavesdropping on communications, or tampering with the availability or integirty of an application hosted behind the load balancer. Additionally, without an X.509 certificate for your domain or load balancer, adversaries can create fake websites with their own X.509 certificates and trick customers or other end-users into disclosing information. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
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
                        "AssetComponent": eeAssetType
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
                                },
                            },
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

@registry.register_check("elasticloadbalancingv2")
def elbv2_tls12_listener_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # valid TLS 1.2 and 1.3 Policies
    goodTls = [
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-FS-1-2-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10",
        "ELBSecurityPolicy-TLS13-1-3-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-2021-06" 
    ]

    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        if elbv2LbType == "application":
            eeAssetType = "Application Load Balancer"
        else:
            eeAssetType = "Network Load Balancer"
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
        myElbv2Listeners = response["Listeners"]
        for listeners in myElbv2Listeners:
            listenerProtocol = str(listeners["Protocol"])
            if listenerProtocol == "HTTPS" or "TLS":
                try:
                    listenerTlsPolicyCheck = str(listeners["SslPolicy"])
                except KeyError:
                    # ignore ALB/NLB without HTTPS/TLS
                    continue
                # Evaluate listener
                if listenerTlsPolicyCheck not in goodTls:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/secure-listener-tls12-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies",
                        "Description": f"The {elbv2LbType} ELBv2 load balancer named {elbv2Name} does not enforce a TLS 1.2 or TLS 1.3 policy and uses the {listenerTlsPolicyCheck} policy. Using security policies that support backwards compatability with TLS 1.0 or TLS 1.1 can lead to downgrade attacks and potential exploitability of legacy ciphersuites, consider upgrading to Forward Secret TLS 1.2 or TLS 1.3 ciphersuites to prevent this. Refer to the remediation instructions to remediate this behavior if not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 security policies and updating them refer to the Update an HTTPS listener for your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-certificates.html",
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
                            "AssetComponent": eeAssetType
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
                                    },
                                    "Other": {
                                        "SslPolicy": listenerTlsPolicyCheck
                                    }
                                },
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
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/secure-listener-tls12-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies",
                        "Description": f"The {elbv2LbType} ELBv2 load balancer named {elbv2Name} enforces a TLS 1.2 or TLS 1.3 policy and uses the {listenerTlsPolicyCheck} policy.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Security Policies section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies",
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
                            "AssetComponent": eeAssetType
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
                                    },
                                    "Other": {
                                        "SslPolicy": listenerTlsPolicyCheck
                                    }
                                }
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
            else:
                continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_drop_invalid_header_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response["Attributes"]
        for attributes in elbv2Attributes:
            if str(attributes["Key"]) == "routing.http.drop_invalid_header_fields.enabled":
                elbv2DropInvalidHeaderCheck = str(attributes["Value"])
                if elbv2DropInvalidHeaderCheck == "false":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " does not drop invalid HTTP header fields. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes",
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
                                    },
                                },
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
                        "RecordState": "ACTIVE",
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " drops invalid HTTP header fields.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes",
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
                                    },
                                },
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
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            else:
                continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_nlb_tls_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        if elbv2LbType == "network":
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            for listeners in response["Listeners"]:
                protocolCheck = str(listeners["Protocol"])
                if protocolCheck == "TLS":
                    response = elbv2.describe_load_balancer_attributes(
                        LoadBalancerArn=elbv2Arn
                    )
                    elbv2Attributes = response["Attributes"]
                    for attributes in elbv2Attributes:
                        if str(attributes["Key"]) == "access_logs.s3.enabled":
                            elbv2LoggingCheck = str(attributes["Value"])
                            if elbv2LoggingCheck == "false":
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": elbv2Arn + "/tls-nlb-logging-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": elbv2Arn,
                                    "AwsAccountId": awsAccountId,
                                    "Types": [
                                        "Software and Configuration Checks/AWS Security Best Practices"
                                    ],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "LOW"},
                                    "Confidence": 99,
                                    "Title": "[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled",
                                    "Description": "Network load balancer "
                                    + elbv2Name
                                    + " does not have access logging enabled. Refer to the remediation instructions to remediate this behavior",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on Network Load Balancer Access Logging and how to configure it refer to the Access Logs for Your Network Load Balancer section of the Network Load Balancers User Guide.",
                                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html",
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
                                        "AssetComponent": "Network Load Balancer"
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
                                    "RecordState": "ACTIVE",
                                }
                                yield finding
                            else:
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": elbv2Arn + "/tls-nlb-logging-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": elbv2Arn,
                                    "AwsAccountId": awsAccountId,
                                    "Types": [
                                        "Software and Configuration Checks/AWS Security Best Practices"
                                    ],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "INFORMATIONAL"},
                                    "Confidence": 99,
                                    "Title": "[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled",
                                    "Description": "Network load balancer "
                                    + elbv2Name
                                    + " has access logging enabled.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on Network Load Balancer Access Logging and how to configure it refer to the Access Logs for Your Network Load Balancer section of the Network Load Balancers User Guide.",
                                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html",
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
                                        "AssetComponent": "Network Load Balancer"
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
                                    "RecordState": "ARCHIVED",
                                }
                                yield finding
                        else:
                            continue
                else:
                    continue
        else:
            continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_alb_http_desync_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled"""
    elbv2 = session.client("elbv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        if elbv2LbType == "application":
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response["Attributes"]
            for attributes in elbv2Attributes:
                if str(attributes["Key"]) == "routing.http.desync_mitigation_mode":
                    elbv2LoggingCheck = str(attributes["Value"])
                    if elbv2LoggingCheck == "monitor":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-alb-http-desync-protection-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + " does not have HTTP Desync protection enabled (it is set to Monitor). Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 HTTP Desync protection and how to configure it refer to the Desync mitigation mode section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode"
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
                                    "NIST CSF V1.1 PR.IP-1",
                                    "NIST SP 800-53 Rev. 4 CM-2",
                                    "NIST SP 800-53 Rev. 4 CM-3",
                                    "NIST SP 800-53 Rev. 4 CM-4",
                                    "NIST SP 800-53 Rev. 4 CM-5",
                                    "NIST SP 800-53 Rev. 4 CM-6",
                                    "NIST SP 800-53 Rev. 4 CM-7",
                                    "NIST SP 800-53 Rev. 4 CM-9",
                                    "NIST SP 800-53 Rev. 4 SA-10",
                                    "AICPA TSC A1.3",
                                    "AICPA TSC CC1.4",
                                    "AICPA TSC CC5.3",
                                    "AICPA TSC CC6.2",
                                    "AICPA TSC CC7.1",
                                    "AICPA TSC CC7.3",
                                    "AICPA TSC CC7.4",
                                    "ISO 27001:2013 A.12.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                    "ISO 27001:2013 A.12.6.2",
                                    "ISO 27001:2013 A.14.2.2",
                                    "ISO 27001:2013 A.14.2.3",
                                    "ISO 27001:2013 A.14.2.4"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-alb-http-desync-protection-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + "has HTTP Desync protection enabled (set to Defensive or Strictest).",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 HTTP Desync protection and how to configure it refer to the Desync mitigation mode section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode"
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
                                        },
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.IP-1",
                                    "NIST SP 800-53 Rev. 4 CM-2",
                                    "NIST SP 800-53 Rev. 4 CM-3",
                                    "NIST SP 800-53 Rev. 4 CM-4",
                                    "NIST SP 800-53 Rev. 4 CM-5",
                                    "NIST SP 800-53 Rev. 4 CM-6",
                                    "NIST SP 800-53 Rev. 4 CM-7",
                                    "NIST SP 800-53 Rev. 4 CM-9",
                                    "NIST SP 800-53 Rev. 4 SA-10",
                                    "AICPA TSC A1.3",
                                    "AICPA TSC CC1.4",
                                    "AICPA TSC CC5.3",
                                    "AICPA TSC CC6.2",
                                    "AICPA TSC CC7.1",
                                    "AICPA TSC CC7.3",
                                    "AICPA TSC CC7.4",
                                    "ISO 27001:2013 A.12.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                    "ISO 27001:2013 A.12.6.2",
                                    "ISO 27001:2013 A.14.2.2",
                                    "ISO 27001:2013 A.14.2.3",
                                    "ISO 27001:2013 A.14.2.4"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                else:
                    continue
        else:
            continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_alb_sg_risk_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access"""
    elbv2 = session.client("elbv2")
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Evaluations
    response = describe_load_balancers(cache, session)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(loadbalancers,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2LbType = str(loadbalancers["Type"])
        # only applicable for ALBs...
        if elbv2LbType == "application":
            elbv2Arn = str(loadbalancers["LoadBalancerArn"])
            elbv2Name = str(loadbalancers["LoadBalancerName"])
            elbv2DnsName = str(loadbalancers["DNSName"])
            elbv2Scheme = str(loadbalancers["Scheme"])
            elbv2VpcId = str(loadbalancers["VpcId"])
            elbv2IpAddressType = str(loadbalancers["IpAddressType"])
            # Create empty list per ELB to store all Listener Ports and SG IDs
            lbSgs = []
            listenerPorts = []
            for sg in loadbalancers["SecurityGroups"]:
                lbSgs.append(str(sg))
            # feed ARN into Listener Call to find all Listeners
            for listener in elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)["Listeners"]:
                # we will stick regular ports AND the redirect action ports (if they exist) into the Port List
                portNumber = str(listener["Port"])
                if portNumber not in listenerPorts:
                    listenerPorts.append(portNumber)
                # now loop the redirects (if there)
                for actions in listener["DefaultActions"]:
                    try:
                        redirectPort = str(actions["RedirectConfig"]["Port"])
                        if redirectPort not in listenerPorts:
                            listenerPorts.append(redirectPort)
                    except KeyError:
                        continue
            # Now we can start to perform evaluations per SG
            for sgid in lbSgs:
                # pass SG ID to Describe SG Rules API via filter and loop each rule
                for sgrs in ec2.describe_security_group_rules(Filters=[{'Name': 'group-id','Values': [sgid]}])["SecurityGroupRules"]:
                    # if the from port or to port range is not within the Listener or Redirect Ports then it's a failing check
                    # we will skip egress rules though
                    if str(sgrs["IsEgress"]) == "True":
                        continue
                    if (str(sgrs["FromPort"]) or str(sgrs["ToPort"])) not in listenerPorts:
                        # this is a failing check - we will stop at the first fail
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-non-listener-sg-port-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access",
                            "Description": f"Application load balancer {elbv2Name} has a Security Group {sgid} that allows access to Ports not associated with any Listener or Redirect Rules. This may allow adversaries to circumvent your load balancer and directly discover or access downstream resources. If this configuration is not intended refer to the remediation guidance.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
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
                                            "SecurityGroups": lbSgs
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
                        break
                    else:
                        # this is a passign check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-non-listener-sg-port-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access",
                            "Description": f"Application load balancer {elbv2Name} does not allow access to Ports not associated with any Listener or Redirect Rules.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
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
                                            "SecurityGroups": lbSgs
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
        else:
            continue

@registry.register_check("elasticloadbalancingv2")
def elbv2_alb_wafv2_coverage_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.9] Application Load Balancers should be protected by AWS Web Application Firewall"""
    wafv2 = session.client("wafv2")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        # only ALBs can be covered by WAF
        if elbv2LbType == "application":
            # attempt to retrieve a WAFv2 WebACL for the resource - errors or other values are not given for a lack of coverage
            # so we end up having to create our own way to determine
            try:
                wafv2.get_web_acl_for_resource(ResourceArn=elbv2Arn)["WebACL"]["ARN"]
                coverage = True
            except KeyError:
                coverage = False
        else:
            coverage = True

        # this is a failing check
        if coverage is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{elbv2Arn}/alb-waf-coverage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{elbv2Arn}/alb-waf-coverage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[ELBv2.9] Application Load Balancers should be protected by AWS Web Application Firewall",
                "Description": f"Application load balancer {elbv2Name} is not protected by an AWS WAF Web ACL. AWS WAF is a web application firewall that lets you monitor the HTTP and HTTPS requests that are forwarded to your protected web application resources. AWS WAF also lets you control access to your content. Based on conditions that you specify, such as the IP addresses that requests originate from or the values of query strings, your protected resource responds to requests either with the requested content, with an HTTP 403 status code (Forbidden), or with a custom response. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on ELBv2 WAF Coverage refer to the What are AWS WAF, AWS Shield, and AWS Firewall Manager? section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"
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
                                "VpcId": elbv2VpcId
                            }
                        }
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
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{elbv2Arn}/alb-waf-coverage-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{elbv2Arn}/alb-waf-coverage-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ELBv2.9] Application Load Balancers should be protected by AWS Web Application Firewall",
                "Description": f"Application load balancer {elbv2Name} is either protected by an AWS WAF Web ACL or it is not an Application Load Balancer and thus cannot be protected. If you do want protection for your Network Load Balancers, you must place an ALB or API Gateway in front.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on ELBv2 WAF Coverage refer to the What are AWS WAF, AWS Shield, and AWS Firewall Manager? section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"
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
                                "VpcId": elbv2VpcId
                            }
                        }
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

@registry.register_check("elasticloadbalancingv2")
def public_alb_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.10] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for lb in describe_load_balancers(cache, session):
        if shodanApiKey == None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(lb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        elbv2Arn = lb["LoadBalancerArn"]
        elbv2Name = lb["LoadBalancerName"]
        elbv2DnsName = lb["DNSName"]
        elbv2LbType = lb["Type"]
        elbv2Scheme = lb["Scheme"]
        elbv2VpcId = lb["VpcId"]
        elbv2IpAddressType = lb["IpAddressType"]
        if (elbv2Scheme == "internet-facing" and elbv2LbType == "application"):
            # Use Google DNS to resolve
            elbv2Ip = google_dns_resolver(elbv2DnsName)
            if elbv2Ip is None:
                continue
            # check if IP indexed by Shodan
            r = requests.get(url=f"{SHODAN_HOSTS_URL}{elbv2Ip}?key={shodanApiKey}").json()
            if str(r) == "{'error': 'No information available for that IP.'}":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{elbv2Arn}/{elbv2DnsName}/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Title": "[ELBv2.10] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Application load balancer {elbv2Name} has not been indexed by Shodan.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": SHODAN_HOSTS_URL
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
                                    "VpcId": elbv2VpcId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                assetPayload = {
                    "LoadBalancer": lb,
                    "Shodan": r
                }
                assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{elbv2Arn}/{elbv2DnsName}/alb-shodan-index-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Effects/Data Exposure"],
                    "CreatedAt": iso8601time,
                    "UpdatedAt": iso8601time,
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "[ELBv2.10] Internet-facing Application Load Balancers should be monitored for being indexed by Shodan",
                    "Description": f"Application load balancer {elbv2Name} has been indexed by Shodan on IP address {elbv2Ip} - resolved from ALB DNS {elbv2DnsName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                            "Url": f"{SHODAN_HOSTS_URL}{elbv2Ip}"
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
                                    "VpcId": elbv2VpcId
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.RA-2",
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 PM-15",
                            "NIST SP 800-53 Rev. 4 PM-16",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "NIST SP 800-53 Rev. 4 SI-5",
                            "AIPCA TSC CC3.2",
                            "AIPCA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.4",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1040",
                            "MITRE ATT&CK T1046",
                            "MITRE ATT&CK T1580",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1592",
                            "MITRE ATT&CK T1595"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
        else:
            continue

## END ??