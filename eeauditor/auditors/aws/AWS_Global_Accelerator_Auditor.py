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
import base64
import json
from botocore.exceptions import ClientError
from check_register import CheckRegister

registry = CheckRegister()

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

def global_region_generator(awsPartition):
    # Global Service Region override
    if awsPartition == "aws":
        globalRegion = "aws-global"
    elif awsPartition == "aws-us-gov":
        globalRegion = "aws-us-gov-global"
    elif awsPartition == "aws-cn":
        globalRegion = "aws-cn-global"
    elif awsPartition == "aws-iso":
        globalRegion = "aws-iso-global"
    elif awsPartition == "aws-isob":
        globalRegion = "aws-iso-b-global"
    elif awsPartition == "aws-isoe":
        globalRegion = "aws-iso-e-global"
    else:
        globalRegion = "aws-global"

    return globalRegion

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

def list_gax_endpoint_groups(cache, session):
    response = cache.get("list_gax_endpoint_groups")
    if response:
        return response
    
    gax = session.client("globalaccelerator", region_name="us-west-2")
    endpointGroups = []

    for accel in gax.list_accelerators()["Accelerators"]:
        for listener in gax.list_listeners(AcceleratorArn=accel["AcceleratorArn"])["Listeners"]:
            for epg in gax.list_endpoint_groups(ListenerArn=listener["ListenerArn"])["EndpointGroups"]:
                endpointGroups.append(epg)

    cache["list_gax_endpoint_groups"] = endpointGroups
    return cache["list_gax_endpoint_groups"]

def list_gax_accelerators(cache, session):
    response = cache.get("list_gax_accelerators")
    if response:
        return response
    
    gax = session.client("globalaccelerator", region_name="us-west-2")
    accelerators = []

    for accel in gax.list_accelerators()["Accelerators"]:
        acceleratorAttributes = gax.describe_accelerator_attributes(
            AcceleratorArn=accel["AcceleratorArn"]
        )["AcceleratorAttributes"]
        accel["AcceleratorAttributes"] = acceleratorAttributes
        accelerators.append(accel)

    cache["list_gax_accelerators"] = accelerators
    return cache["list_gax_accelerators"]

@registry.register_check("globalaccelerator")
def aws_gax_unhealthy_endpoint_group_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GlobalAccelerator.1] AWS Global Accelerator endpoint groups should not have unhealthy endpoints"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for epg in list_gax_endpoint_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(epg,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        endpointGroupArn = epg["EndpointGroupArn"]
        endpointGroupId = endpointGroupArn.split("/")[5]
        endpointGroupRegion = epg["EndpointGroupRegion"]
        endpointHealthCheckProtocol = epg["HealthCheckProtocol"]
        # Use a list comprehension to check for unhealthy endpoints in the Endpoint Group
        unhealthyEndpoints = [endpoint for endpoint in epg["EndpointDescriptions"] if endpoint["HealthState"] == "UNHEALTHY"]
        if unhealthyEndpoints:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{endpointGroupArn}/aws-gax-unhealthy-endpoint-group-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{endpointGroupArn}/aws-gax-unhealthy-endpoint-group-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GlobalAccelerator.1] AWS Global Accelerator endpoint groups should not have unhealthy endpoints",
                "Description": f"AWS Global Accelerator endpoint group {endpointGroupId} has one or more unhealthy endpoints. Endpoints for standard accelerators in AWS Global Accelerator can be Network Load Balancers, Application Load Balancers, Amazon EC2 instances, or Elastic IP addresses. With standard accelerators, a static IP address serves as a single point of contact for clients, and Global Accelerator then distributes incoming traffic across healthy endpoints. Global Accelerator directs traffic to endpoints by using the port (or port range) that you specify for the listener that the endpoint group for the endpoint belongs to. Global Accelerator continually monitors the health of all endpoints that are included in a standard endpoint group. It routes traffic only to the active endpoints that are healthy. If Global Accelerator does not have any healthy endpoints to route traffic to, it routes traffic to all endpoints. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the health of endpoints refer to the Endpoints in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoints.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Endpoint Group"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorEndpointGroup",
                        "Id": endpointGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EndpointGroupId": endpointGroupId,
                                "EndpointGroupRegion": endpointGroupRegion,
                                "HealthCheckProtocol": endpointHealthCheckProtocol
                            }
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
                "Id": f"{endpointGroupArn}/aws-gax-unhealthy-endpoint-group-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{endpointGroupArn}/aws-gax-unhealthy-endpoint-group-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GlobalAccelerator.1] AWS Global Accelerator endpoint groups should not have unhealthy endpoints",
                "Description": f"AWS Global Accelerator endpoint group {endpointGroupId} does not have any unhealthy endpoints.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the health of endpoints refer to the Endpoints in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoints.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Endpoint Group"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorEndpointGroup",
                        "Id": endpointGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EndpointGroupId": endpointGroupId,
                                "EndpointGroupRegion": endpointGroupRegion,
                                "HealthCheckProtocol": endpointHealthCheckProtocol
                            }
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

@registry.register_check("globalaccelerator")
def aws_gax_accelerators_flow_logs_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GlobalAccelerator.2] AWS Global Accelerator accelerators should have flow logs enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accel in list_gax_accelerators(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(accel,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        acceleratorArn = accel["AcceleratorArn"]
        acceleratorName = accel["Name"]
        acceleratorIpAddressType = accel["IpAddressType"]
        acceleratorDnsName = accel["DnsName"]
        # this is a failing check
        if accel["AcceleratorAttributes"]["FlowLogsEnabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{acceleratorArn}/aws-gax-accelerator-flow-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{acceleratorArn}/aws-gax-accelerator-flow-logs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GlobalAccelerator.2] AWS Global Accelerator accelerators should have flow logs enabled",
                "Description": f"AWS Global Accelerator accelerator {acceleratorName} does not have flow logs enabled. Flow logs enable you to capture information about the IP address traffic going to and from network interfaces in your accelerator in AWS Global Accelerator. Flow log data is published to Amazon S3, where you can retrieve and view your data after you've created a flow log. A flow log record represents a network flow in your flow log. Each record captures the network flow for a specific 5-tuple, for a specific capture window. A 5-tuple is a set of five different values that specify the source, destination, and protocol for an IP flow. The capture window is a duration of time during which the flow logs service aggregates data before publishing flow log records. The capture window is up to 1 minute. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on accelerator flow logs refer to the Flow logs in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": acceleratorName,
                                "IpAddressType": acceleratorIpAddressType,
                                "DnsName": acceleratorDnsName
                            }
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
                "Id": f"{acceleratorArn}/aws-gax-accelerator-flow-logs-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{acceleratorArn}/aws-gax-accelerator-flow-logs-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GlobalAccelerator.2] AWS Global Accelerator accelerators should have flow logs enabled",
                "Description": f"AWS Global Accelerator accelerator {acceleratorName} does have flow logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on accelerator flow logs refer to the Flow logs in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": acceleratorName,
                                "IpAddressType": acceleratorIpAddressType,
                                "DnsName": acceleratorDnsName
                            }
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

@registry.register_check("globalaccelerator")
def global_accelerator_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GlobalAccelerator.3] AWS Global Accelerator accelerators should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accel in list_gax_accelerators(cache, session):
        if shodanApiKey is None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(accel,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        acceleratorArn = accel["AcceleratorArn"]
        acceleratorName = accel["Name"]
        acceleratorIpAddressType = accel["IpAddressType"]
        acceleratorDnsName = accel["DnsName"]
        gaxDomainIp = google_dns_resolver(acceleratorDnsName)
        if gaxDomainIp is None:
            continue
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{gaxDomainIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{acceleratorArn}/{acceleratorDnsName}/global-accelerator-shodan-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": acceleratorArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[GlobalAccelerator.3] AWS Global Accelerator accelerators should be monitored for being indexed by Shodan",
                "Description": f"AWS Global Accelerator accelerator {acceleratorName} has not been indexed by Shodan.",
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
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": acceleratorName,
                                "IpAddressType": acceleratorIpAddressType,
                                "DnsName": acceleratorDnsName
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
                "Accelerator": accel,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{acceleratorArn}/{acceleratorDnsName}/global-accelerator-shodan-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": acceleratorArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[GlobalAccelerator.3] AWS Global Accelerator accelerators should be monitored for being indexed by Shodan",
                "Description": f"AWS Global Accelerator accelerator {acceleratorName} has been indexed by Shodan on IP address {gaxDomainIp} - resolved from DNS name {acceleratorDnsName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{gaxDomainIp}"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "AWS Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": acceleratorName,
                                "IpAddressType": acceleratorIpAddressType,
                                "DnsName": acceleratorDnsName
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

## END ??