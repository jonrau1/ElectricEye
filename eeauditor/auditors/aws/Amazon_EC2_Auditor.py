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

import logging
import tomli
import os
import sys
from botocore.config import Config
from check_register import CheckRegister
from botocore.exceptions import ClientError
import requests
import datetime
from dateutil.parser import parse
import base64
import json

logger = logging.getLogger("AwsEc2Auditor")

SHODAN_HOSTS_URL = "https://api.shodan.io/shodan/host/"

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

def describe_elastic_ips(cache, session):
    response = cache.get("describe_elastic_ips")
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_elastic_ips"] = ec2.describe_addresses()["Addresses"]
    return cache["describe_elastic_ips"]

def get_cisa_kev():
    """
    Retrieves the U.S. CISA's Known Exploitable Vulnerabilities (KEV) Catalog and returns a list of CVE ID's
    """

    rawKev = json.loads(requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").text)["vulnerabilities"]

    kevCves = [cve["cveID"] for cve in rawKev]

    return kevCves

def find_exploitable_vulnerabilities_for_instance(session, instanceId):
    """
    This function uses the CISA KEV and Amazon Inspector V2 to determine if an EC2 Instance has any vulnerabilities
    and if it does, if they are exploitable. A Bool for the exploitability, a reason for not having any, and a list
    of explotiable vulnerabilities are returned
    """
    inspector = session.client("inspector2")

    kev = get_cisa_kev()

    # Filter Inspector findings to the specific Instance and for Package Vulnerabilities only (ignore Reachability)
    inspectorFindings = inspector.list_findings(
        filterCriteria={
            "resourceId": [
                {
                    "comparison": "EQUALS",
                    "value": instanceId
                }
            ],
            "findingType": [
                {
                    "comparison": "EQUALS",
                    "value": "PACKAGE_VULNERABILITY"
                }
            ]
        }
    )["findings"]
    if not inspectorFindings:
        exploitable = False
        exploitableCves = []
    # Use a list comprehension to pull out any Inspector vulnerabilities which are tagged as explotiable or that are in the KEV and extend the list above
    exploitableCves = [
        finding["packageVulnerabilityDetails"]["vulnerabilityId"] for finding in inspectorFindings
        if finding["status"] == "ACTIVE" 
        and finding["exploitAvailable"] == "YES"
        or finding["packageVulnerabilityDetails"]["vulnerabilityId"] in kev
    ]
    if not exploitableCves:
        exploitable = False
        exploitableCves = []
    else:
        exploitable = True

    return exploitable, exploitableCves

def get_shodan_api_key(cache):
    import boto3

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
        logger.error("Invalid option for [global.credLocation]. Must be one of %s.", validCredLocations)
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
            except ClientError as err:
                logger.warning("Error retrieving API Key from AWS Systems Manager Parameter Store, skipping all Shodan checks, error: %s", err)
                apiKey = None

        # Retrieve the credential from AWS Secrets Manager
        elif credLocation == "AWS_SECRETS_MANAGER":
            try:
                apiKey = asm.get_secret_value(
                    SecretId=shodanCredValue,
                )["SecretString"]
            except ClientError as err:
                logger.warning("Error retrieving API Key from AWS Secrets Manager, skipping all Shodan checks, error: %s", err)
                apiKey = None
        
    cache["get_shodan_api_key"] = apiKey
    return cache["get_shodan_api_key"]

@registry.register_check("ec2")
def ec2_imdsv2_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.1] Amazon EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)"""
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
                    "Title": "[EC2.1] Amazon EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)",
                    "Description": f"Amazon EC2 Instance {instanceId} is not configured to use instance metadata service V2 (IMDSv2). IMDSv2 adds new “belt and suspenders” protections for four types of vulnerabilities that could be used to try to access the IMDS. These new protections go well beyond other types of mitigations, while working seamlessly with existing mitigations such as restricting IAM roles and using local firewall rules to restrict access to the IMDS. Refer to the remediation instructions if this configuration is not intended",
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
                            "NIST CSF V1.1 PR.AC-3",
                            "NIST CSF V1.1 PR.AC-4",
                            "NIST CSF V1.1 PR.DS-5",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-5",
                            "NIST SP 800-53 Rev. 4 AC-6",
                            "NIST SP 800-53 Rev. 4 AC-14",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-17",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-20",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 PE-19",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "NIST SP 800-53 Rev. 4 PS-6",
                            "NIST SP 800-53 Rev. 4 SC-7",
                            "NIST SP 800-53 Rev. 4 SC-8",
                            "NIST SP 800-53 Rev. 4 SC-13",
                            "NIST SP 800-53 Rev. 4 SC-15",
                            "NIST SP 800-53 Rev. 4 SC-31",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC6.3",
                            "AICPA TSC CC6.6",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.2",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.7.1.2",
                            "ISO 27001:2013 A.7.3.1",
                            "ISO 27001:2013 A.8.2.2",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.9.1.1",
                            "ISO 27001:2013 A.9.1.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.4.1",
                            "ISO 27001:2013 A.9.4.4",
                            "ISO 27001:2013 A.9.4.5",
                            "ISO 27001:2013 A.10.1.1",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.11.1.5",
                            "ISO 27001:2013 A.11.2.1",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.1.3",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.13.2.4",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.6",
                            "CIS Amazon Web Services Foundations Benchmark V3.0 5.6"
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
                    "Title": "[EC2.1] Amazon EC2 Instances should be configured to use instance metadata service V2 (IMDSv2)",
                    "Description": f"Amazon EC2 Instance {instanceId} is using instance metadata service V2 (IMDSv2). IMDSv2 adds new “belt and suspenders” protections for four types of vulnerabilities that could be used to try to access the IMDS. These new protections go well beyond other types of mitigations, while working seamlessly with existing mitigations such as restricting IAM roles and using local firewall rules to restrict access to the IMDS. Refer to the remediation instructions if this configuration is not intended",
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
                            "NIST CSF V1.1 PR.AC-3",
                            "NIST CSF V1.1 PR.AC-4",
                            "NIST CSF V1.1 PR.DS-5",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-5",
                            "NIST SP 800-53 Rev. 4 AC-6",
                            "NIST SP 800-53 Rev. 4 AC-14",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-17",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-20",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 PE-19",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "NIST SP 800-53 Rev. 4 PS-6",
                            "NIST SP 800-53 Rev. 4 SC-7",
                            "NIST SP 800-53 Rev. 4 SC-8",
                            "NIST SP 800-53 Rev. 4 SC-13",
                            "NIST SP 800-53 Rev. 4 SC-15",
                            "NIST SP 800-53 Rev. 4 SC-31",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC6.3",
                            "AICPA TSC CC6.6",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.6.1.2",
                            "ISO 27001:2013 A.6.2.1",
                            "ISO 27001:2013 A.6.2.2",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.7.1.2",
                            "ISO 27001:2013 A.7.3.1",
                            "ISO 27001:2013 A.8.2.2",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.9.1.1",
                            "ISO 27001:2013 A.9.1.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.4.1",
                            "ISO 27001:2013 A.9.4.4",
                            "ISO 27001:2013 A.9.4.5",
                            "ISO 27001:2013 A.10.1.1",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.11.1.5",
                            "ISO 27001:2013 A.11.2.1",
                            "ISO 27001:2013 A.11.2.6",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.1.3",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.13.2.3",
                            "ISO 27001:2013 A.13.2.4",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3",
                            "CIS Amazon Web Services Foundations Benchmark V2.0 5.6",
                            "CIS Amazon Web Services Foundations Benchmark V3.0 5.6"
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
    """[EC2.2] Amazon EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves"""
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
                "Title": "[EC2.2] Amazon EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves",
                "Description": "Amazon EC2 Instance "
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
                "Title": "[EC2.2] Amazon EC2 Instances running critical or high-security workloads should be configured to use Secure Enclaves",
                "Description": "Amazon EC2 Instance "
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
    """[EC2.3] Amazon EC2 Instances should not be publicly discoverable on the internet"""
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
                "Id": f"{instanceArn}/ec2-public-facing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-public-facing-check",
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
                "Title": "[EC2.3] Amazon EC2 Instances should not be publicly discoverable on the internet",
                "Description": "Amazon EC2 Instance "
                + instanceId
                + " is not internet-facing (due to not having a Public DNS).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amazon EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
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
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-public-facing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-public-facing-check",
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
                "Title": "[EC2.3] Amazon EC2 Instances should not be publicly discoverable on the internet",
                "Description": "Amazon EC2 Instance "
                + instanceId
                + " is internet-facing (due to having a Public DNS), instances should be behind AWS Elastic Load Balancers, CloudFront Distributions, or a 3rd-party CDN/Load Balancer to avoid any vulnerabilities on the middleware or the operating system from being exploited directly. Additionally, load balancing can increase high availability and resilience of applications hosted on EC2. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Amazon EC2 Instances should be rebuilt in Private Subnets within your VPC and placed behind Load Balancers. To learn how to attach Instances to a public-facing load balancer refer to the How do I attach backend instances with private IP addresses to my internet-facing load balancer in ELB? post within the AWS Premium Support Knowledge Center",
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
            
@registry.register_check("ec2")
def ec2_source_dest_verification_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.4] Amazon EC2 Instances should use Source-Destination checks unless absolutely not required"""
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
                "Title": "[EC2.4] Amazon EC2 Instances should use Source-Destination checks unless absolutely not required",
                "Description": f"Amazon EC2 Instance {instanceId} does have have the Source-Destination Check enabled. Typically, this is done for self-managed Network Address Translation (NAT), Forward Proxies (such as Squid, for URL Filtering/DNS Protection) or self-managed Firewalls (ModSecurity). These settings should be verified, and underlying technology must be patched to avoid exploits or availability loss. Refer to the remediation instructions if this configuration is not intended.",
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
                "Title": "[EC2.4] Amazon EC2 Instances should use Source-Destination checks unless absolutely not required",
                "Description": f"Amazon EC2 Instance {instanceId} has the Source-Destination Check enabled.",
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
    serialConsoleArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:serial-console-access"
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
                    "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
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
                    "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that is {AmiAge.days} days old",
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
                    "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
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
                    "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
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
                    "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that has a status of: {amiState}",
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
                "Description": f"Amazon EC2 Instance {instanceId} is using an AMI that has a status of: deregistered",
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
                "Description": f"Amazon EC2 Instance {instanceId} is not managed by AWS Systems Manager. Systems Manager (SSM) enables automated activities such as patching, configuration management, software inventory management and more. Not having instances managed by SSM can degrade the effectiveness of important security processes. This status can be due to the Instance being stopped or hibernated for too long and being removed from SSM tracking, lacking an instance profile that provides permissions to the SSM APIs, or having an SSM Agent that is deprecated. Refer to the remediation instructions if this configuration is not intended.",
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
                "Description": f"Amazon EC2 Instance {instanceId} is managed by AWS Systems Manager.",
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
def ec2_instance_linux_latest_ssm_agent_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
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
                "Description": f"Amazon EC2 Instance {instanceId} is a Linux-based platform which does not have the latest SSM Agent installed, or it is not covered by AWS SSM at all. Not having the latest SSM Agent can lead to issues with patching, configuration management, inventory management, and/or vulnerability management activities. Refer to the remediation instructions if this configuration is not intended.",
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
                "Description": f"Amazon EC2 Instance {instanceId} is either a Linux-based platform and has the latest SSM Agent installed or is not a Linux-based platform.",
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
def ec2_instance_ssm_association_successful_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
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
                "Description": f"Amazon EC2 Instance {instanceId} has failed its last Systems Manager State Manager Association or is not onboarded AWS SSM at all. Associations are State Manager automation constructs which encapsulate execution of SSM Documents such as Patching, software configuration, and SSM Agent updates onto an instance. A failed Association can represent the failure of a critical process and should be reviewed. Refer to the remediation instructions for more information on working with State Manager Associations.",
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
                "Description": f"Amazon EC2 Instance {instanceId} has passed its last Systems Manager State Manager Association.",
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
def ec2_instance_patch_manager_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.12] Amazon EC2 instances should be actively managed by and reporting patch information to AWS Systems Manager Patch Manager"""
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
        
        # Check if there any patches at all       
        if not ssm.describe_instance_patches(InstanceId=instanceId)["Patches"]:
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
                "Title": "[EC2.12] Amazon EC2 instances should be actively managed by and reporting patch information to AWS Systems Manager Patch Manager",
                "Description": f"Amazon EC2 Instance {instanceId} does not have any patch information recorded and is likely not managed by Patch Manager. Patch Manager automates the installation and application of security, performance, and major version upgrades and KBs onto your instances, reducing exposure to vulnerabilities and other weaknesses. Without automatic patching at scale, vulnerabilities can quickly manifest within a given cloud environment leading to potential avenues of attack for adversaries and other unauthorized actors. Refer to the remediation instructions if this configuration is not intended.",
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
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.18.2.3",
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
                "Title": "[EC2.12] Amazon EC2 instances should be actively managed by and reporting patch information to AWS Systems Manager Patch Manager",
                "Description": f"Amazon EC2 Instance {instanceId} has patches applied by AWS Systems Manager Patch Manager. You should still review Patch Compliance information to ensure that all required patches were successfully applied.",
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
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.1.1",
                        "ISO 27001:2013 A.8.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.18.2.3",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ec2_instance_scanned_by_inspector_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.13] Amazon EC2 instances should should be scanned for vulnerabilities by Amazon Inspector V2"""
    inspector = session.client("inspector2",config=config)
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

        # Check if the EC2 instance is being scanned - sure, this will fail if Inspector isn't enabled for EC2
        # but sometimes some bonehead may not scan it. Also it'll fail if the instance is stopped for too long
        coverage = inspector.list_coverage(
            filterCriteria={
                "resourceId": [
                    {
                        "comparison": "EQUALS",
                        "value": instanceId
                    }
                ]
            }
        )["coveredResources"]

        if not coverage:
            resourceScanned = False
        else:
            if coverage[0]["scanStatus"]["statusCode"] == "ACTIVE":
                resourceScanned = True
            else:
                resourceScanned = False
           
        if resourceScanned is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-vulnerability-scanning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-vulnerability-scanning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EC2.13] Amazon EC2 instances should should be scanned for vulnerabilities by Amazon Inspector V2",
                "Description": f"Amazon EC2 Instance {instanceId} is not being scanned for vulnerabilities by Amazon Inspector V2. Amazon Inspector scans operating system packages and programming language packages installed on your Amazon EC2 instances for vulnerabilities. Amazon Inspector also scans your EC2 instances for network reachability issues. To perform an EC2 scan Amazon Inspector extracts software package metadata from your EC2 instances. Then, Amazon Inspector compares this metadata against rules collected from security advisories to produce findings. Amazon Inspector uses AWS Systems Manager (SSM) and the SSM Agent to collect information about the software application inventory of your EC2 instances. This data is then scanned by Amazon Inspector for software vulnerabilities. Amazon Inspector can only scan for software vulnerabilities in operating systems supported by Systems Manager. Additionally, using EC2 Deep Inspection Amazon Inspector can detect package vulnerabilities for application programming language packages in your Linux-based Amazon EC2 instances. Amazon Inspector scans default paths for programming language package libraries. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on how Inspector V2 works for EC2 instance vulnerability management and how to configure it refer to the Scanning Amazon EC2 instances with Amazon Inspector section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
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
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-vulnerability-scanning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-vulnerability-scanning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.13] Amazon EC2 instances should should be scanned for vulnerabilities by Amazon Inspector V2",
                "Description": f"Amazon EC2 Instance {instanceId} is being scanned for vulnerabilities by Amazon Inspector V2.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on how Inspector V2 works for EC2 instance vulnerability management and how to configure it refer to the Scanning Amazon EC2 instances with Amazon Inspector section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
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
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ec2_instance_exploitable_vulnerability_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.14] Amazon EC2 instances with known exploitable vulnerabilities should be immediately remediated"""
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

        # Call helper function to see if the instance has explotiable vulns, and if so, which ones
        exploitInfo = find_exploitable_vulnerabilities_for_instance(session, instanceId)        
           
        if exploitInfo[0] is True:
            cveSentence = ", ".join(exploitInfo[1])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-exploitable-vulnerabilities-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-exploitable-vulnerabilities-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[EC2.14] Amazon EC2 instances with known exploitable vulnerabilities should be immediately remediated",
                "Description": f"Amazon EC2 Instance {instanceId} has at least one active and exploitable vulnerability and should be immediately remediated. The following CVEs are exploitable: {cveSentence}. Amazon Inspector scans operating system packages and programming language packages installed on your Amazon EC2 instances for vulnerabilities. Amazon Inspector also scans your EC2 instances for network reachability issues. To perform an EC2 scan Amazon Inspector extracts software package metadata from your EC2 instances. Then, Amazon Inspector compares this metadata against rules collected from security advisories to produce findings. Amazon Inspector uses AWS Systems Manager (SSM) and the SSM Agent to collect information about the software application inventory of your EC2 instances. This data is then scanned by Amazon Inspector for software vulnerabilities. Amazon Inspector can only scan for software vulnerabilities in operating systems supported by Systems Manager. Additionally, using EC2 Deep Inspection Amazon Inspector can detect package vulnerabilities for application programming language packages in your Linux-based Amazon EC2 instances. Amazon Inspector scans default paths for programming language package libraries. ElectricEye uses the Amazon Inspector Vulnerability Intelligence Database and the CISA KEV catalog to determine if a CVE is exploitable. Exploitable vulnerabilities that are public have a higher chance of being actively targeted by adversaries and can cause irreperable harm to your organization. These vulnerabilities should be remediated or otherwise countered as soon as possible. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on how Inspector V2 works for EC2 instance vulnerability management and how to configure it refer to the Scanning Amazon EC2 instances with Amazon Inspector section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
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
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST CSF V1.1 ID.RA-2",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 PM-15",
                        "NIST SP 800-53 Rev. 4 PM-16",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.6.1.4",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/ec2-exploitable-vulnerabilities-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/ec2-exploitable-vulnerabilities-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.14] Amazon EC2 instances with known exploitable vulnerabilities should be immediately remediated",
                "Description": f"Amazon EC2 Instance {instanceId} does not have any exploitable vulnerabilities. This can be because Amazon Inspector V2 is not enabled, is not enabled to scan EC2 instances, or because this particular instance is not being scanned due to exigent circumstances or just because someone on your vulnerability management team messed up. They done goofed, yo! Anyway...if your instance does have vulnerabilities without public exploits does not mean your should not triage and treat them for remediation or other mitigating controls. Use multiple additional sources of intelligence such as ExploitDB, deceptive technologies, Packet Storm, as well as EPSS to help drive your remediation prioritization efforts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on how Inspector V2 works for EC2 instance vulnerability management and how to configure it refer to the Scanning Amazon EC2 instances with Amazon Inspector section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
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
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST CSF V1.1 ID.RA-2",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 PM-15",
                        "NIST SP 800-53 Rev. 4 PM-16",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.6.1.4",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def aws_elastic_ip_assigned_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.15] Amazon Elastic IP (EIP) addresses should not be unassigned"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for eip in describe_elastic_ips(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(eip,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        allocationId = eip["AllocationId"]
        publicIp = eip["PublicIp"]
        eipArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:elastic-ip/{allocationId}"     
           
        if "AssociationId" not in eip:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{eipArn}/elastic-ip-is-unassigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eipArn}/elastic-ip-is-unassigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.15] Amazon Elastic IP (EIP) addresses should not be unassigned",
                "Description": f"Amazon Elastic IP (EIP) address {allocationId} is not assigned. An Elastic IP address is a static IPv4 address designed for dynamic cloud computing. An Elastic IP address is allocated to your AWS account, and is yours until you release it. By using an Elastic IP address, you can mask the failure of an instance or software by rapidly remapping the address to another instance in your account. Alternatively, you can specify the Elastic IP address in a DNS record for your domain, so that your domain points to your instance. To ensure efficient use of Elastic IP addresses, we impose a small hourly charge if an Elastic IP address is not associated with a running instance, or if it is associated with a stopped instance or an unattached network interface. Ensure unassigned addresses are released so that you will not be charged for them, and while rare, you can prevent crafty adversaries from assigning the address to illicit infrastructure in your account that can circumvent trusted network access restrictions. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Elastic IPs refer to the Elastic IP addresses section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html"
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
                    "AssetComponent": "Elastic IP Address"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Eip": {
                                "PublicIp": publicIp,
                                "AllocationId": allocationId
                            }
                        }
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
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{eipArn}/elastic-ip-is-unassigned-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eipArn}/elastic-ip-is-unassigned-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.15] Amazon Elastic IP (EIP) addresses should not be unassigned",
                "Description": f"Amazon Elastic IP (EIP) address {allocationId} is assigned.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about Elastic IPs refer to the Elastic IP addresses section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html"
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
                    "AssetComponent": "Elastic IP Address"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Eip": {
                                "PublicIp": publicIp,
                                "AllocationId": allocationId
                            }
                        }
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def public_ec2_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.16] Amazon EC2 instances with public IP addresses should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in describe_instances(cache, session):
        if shodanApiKey is None:
            continue
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
            ec2PublicIp = str(i["PublicIpAddress"])
        except KeyError:
            continue
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{ec2PublicIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/{ec2PublicIp}/ec2-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/{ec2PublicIp}/ec2-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[EC2.16] Amazon EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"Amazon EC2 instance {instanceId} has not been indexed by Shodan.",
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
                "Instance": i,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{instanceArn}/{ec2PublicIp}/ec2-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{instanceArn}/{ec2PublicIp}/ec2-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[EC2.16] Amazon EC2 instances with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"Amazon EC2 instance {instanceId} has been indexed by Shodan on IP {ec2PublicIp}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{ec2PublicIp}"
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

@registry.register_check("ec2")
def aws_elastic_ip_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.17] Amazon Elastic IP addresses with public IP addresses should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for eip in describe_elastic_ips(cache, session):
        if shodanApiKey is None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(eip,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        allocationId = eip["AllocationId"]
        publicIp = eip["PublicIp"]
        eipArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:elastic-ip/{allocationId}"  
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{publicIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{eipArn}/{publicIp}/eip-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eipArn}/{publicIp}/eip-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[EC2.17] gbes with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"Amazon Elastic IP address {allocationId} has not been indexed by Shodan.",
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
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Elastic IP Address"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Eip": {
                                "PublicIp": publicIp,
                                "AllocationId": allocationId
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
                "Instance": eip,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{eipArn}/{publicIp}/eip-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{eipArn}/{publicIp}/eip-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[EC2.17] Amazon Elastic IP addresses with public IP addresses should be monitored for being indexed by Shodan",
                "Description": f"Amazon Elastic IP address {allocationId} has been indexed by Shodan on IP {publicIp}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{publicIp}"
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
                    "AssetComponent": "Elastic IP Address"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Eip",
                        "Id": eipArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Eip": {
                                "PublicIp": publicIp,
                                "AllocationId": allocationId
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