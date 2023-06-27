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

def paginate_distributions(cache, session):
    cloudfront = session.client("cloudfront")

    itemList = []
    response = cache.get("items")
    if response:
        return response
    paginator = cloudfront.get_paginator("list_distributions")
    if paginator:
        for page in paginator.paginate():
            try:
                for items in page["DistributionList"]["Items"]:
                    itemList.append(items)
            except KeyError:
                return {}
        cache["items"] = itemList
        return cache["items"]

@registry.register_check("cloudfront")
def cloudfront_active_trusted_signers_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.1] Cloudfront Distributions with active Trusted Signers should use Key Pairs"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["ActiveTrustedSigners"]["Enabled"]) == 'True':
            for i in distro["ActiveTrustedSigners"]["Items"]:
                # this is a failing check
                if i["KeyPairIds"]["Quantity"] == 0:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/cloudfront-active-trusted-signers-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[CloudFront.1] Cloudfront Distributions with active Trusted Signers should use Key Pairs",
                        "Description": f"CloudFront Distribution {distributionId} has trusted signers without key pairs. Each signer that you use to create CloudFront signed URLs or signed cookies must have a public-private key pair. AWS recommends that you use trusted key groups with signed URLs and signed cookies. For more information see the remediation section.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on key pairs for CloudFront trusted signers refer to the Creating CloudFront Key Pairs for Your Trusted Signers section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus
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
                    break
                # this is a passing check
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/cloudfront-active-trusted-signers-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CloudFront.1] Cloudfront Distributions with active Trusted Signers should use Key Pairs",
                        "Description": f"CloudFront Distribution {distributionId} has trusted signers with key pairs.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on key pairs for CloudFront trusted signers refer to the Creating CloudFront Key Pairs for Your Trusted Signers section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus
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
                    break
        else:
            # this is a passing check since signers are not used
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-active-trusted-signers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.1] Cloudfront Distributions with active Trusted Signers should use Key Pairs",
                "Description": f"CloudFront Distribution {distributionId} does not have any active trusted signers and is not in scope for this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on key pairs for CloudFront trusted signers refer to the Creating CloudFront Key Pairs for Your Trusted Signers section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_origin_shield_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.2] Cloudfront Distributions Origins should have Origin Shield enabled"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if not distro["DistributionConfig"]["Origins"]["Items"]:
            continue
        else:
            for orig in distro["DistributionConfig"]["Origins"]["Items"]:
                originId = orig["Id"]
                if str(orig["OriginShield"]["Enabled"]) == "False":
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/{originId}/cloudfront-originshield-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[CloudFront.2] Cloudfront Distributions Origins should have Origin Shield enabled",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} does not have Origin Shield enabled. CloudFront Origin Shield is an additional layer in the CloudFront caching infrastructure that helps to minimize your origin's load, improve its availability, and reduce its operating costs. For more information see the remediation section.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Origin Shield for CloudFront, refer to the Using Amazon CloudFront Origin Shield section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
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
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/{originId}/cloudfront-originshield-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CloudFront.2] Cloudfront Distributions Origins should have Origin Shield enabled",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} has Origin Shield enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Origin Shield for CloudFront, refer to the Using Amazon CloudFront Origin Shield section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
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

@registry.register_check("cloudfront")
def cloudfront_default_viewer_cert_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.3] Cloudfront Distributions should not use the default Viewer certificate"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["ViewerCertificate"]["CloudFrontDefaultCertificate"]) == "True":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-cert-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudFront.3] Cloudfront Distributions should not use the default Viewer certificate",
                "Description": f"CloudFront Distribution {distributionId} uses the Cloudfront default Viewer certificate. If you're using your own domain name, such as example.com, you need to use an SSL/TLS certificate provided by AWS Certificate Manager (ACM), or import a certificate from a third-party certificate authority into ACM. Using your own certificate will lessen the chance of abuse, attacks against supplier certificates, and increase logging capabilities and revocation if required. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on CloudFront HTTPS settings refer to the Requiring HTTPS for communication between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-cert-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.3] Cloudfront Distributions should not use the default Viewer certificate",
                "Description": f"CloudFront Distribution {distributionId} does not use the Cloudfront default Viewer certificate.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on CloudFront HTTPS settings refer to the Requiring HTTPS for communication between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_georestriction_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.4] Cloudfront Distributions should have a Georestriction configured"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        geoBlockType = str(distro["DistributionConfig"]["Restrictions"]["GeoRestriction"]["RestrictionType"])
        if geoBlockType == "none":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-geo-restriction-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudFront.4] Cloudfront Distributions should have a Georestriction configured",
                "Description": f"CloudFront Distribution {distributionId} does not use any Geostrictictions. You can use geographic restrictions, sometimes known as geo blocking, to prevent users in specific geographic locations from accessing content that you're distributing through a CloudFront distribution. Geo blocking can help meet regulatory, compliance, and/or privacy controls such as ensuring content is only available to certain populations or implementing embargoes or sanctions required by the United States Department of the Treasury. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Geo Restriction for CloudFront, refer to the Restricting the Geographic Distribution of Your Content section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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
            restrictedCountries = str(distro["DistributionConfig"]["Restrictions"]["GeoRestriction"]["Items"]).replace("'","").replace("[","").replace("]","")
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-geo-restriction-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.4] Cloudfront Distributions should have a Georestriction configured",
                "Description": f"CloudFront Distribution {distributionId} uses a {geoBlockType} Geostrictiction against the following countries: {restrictedCountries}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Geo Restriction for CloudFront, refer to the Restricting the Geographic Distribution of Your Content section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_field_level_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.5] Cloudfront Distributions should implement Field-Level Encryption in default cache behavior"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["DefaultCacheBehavior"]["FieldLevelEncryptionId"]) == "":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-field-level-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudFront.5] Cloudfront Distributions should implement Field-Level Encryption in default cache behavior",
                "Description": f"CloudFront Distribution {distributionId} does not implement Field-Level Encryption. With Amazon CloudFront, you can enforce secure end-to-end connections to origin servers by using HTTPS. Field-level encryption adds an additional layer of security that lets you protect specific data throughout system processing so that only certain applications can see it. Field-level encryption allows you to enable your users to securely upload sensitive information to your web servers. The sensitive information provided by your users is encrypted at the edge, close to the user, and remains encrypted throughout your entire application stack. This encryption ensures that only applications that need the data—and have the credentials to decrypt it—are able to do so. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Field-Level Encryption for CloudFront, refer to the Using Field-Level Encryption to Help Protect Sensitive Data section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
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
                "Id": f"{distributionArn}/cloudfront-field-level-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.5] Cloudfront Distributions should implement Field-Level Encryption in default cache behavior",
                "Description": f"CloudFront Distribution {distributionId} uses Field-Level Encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Field-Level Encryption for CloudFront, refer to the Using Field-Level Encryption to Help Protect Sensitive Data section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudfront")
def cloudfront_waf_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.6] Cloudfront Distributions should use a Web Application Firewall"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["WebACLId"]) == "":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-waf-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudFront.6] Cloudfront Distributions should use a Web Application Firewall",
                "Description": f"CloudFront Distribution {distributionId} does not use a Web Application Firewall. AWS WAF is a web application firewall that lets you monitor the HTTP and HTTPS requests that are forwarded to CloudFront, and lets you control access to your content. Based on conditions that you specify, such as the values of query strings or the IP addresses that requests originate from, CloudFront responds to requests either with the requested content or with an HTTP status code 403 (Forbidden). You can also configure CloudFront to return a custom error page when a request is blocked. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WAF for CloudFront, refer to the Using AWS WAF to Control Access to Your Content section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-waf-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.6] Cloudfront Distributions should use a Web Application Firewall",
                "Description": f"CloudFront Distribution {distributionId} uses a Web Application Firewall.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WAF for CloudFront, refer to the Using AWS WAF to Control Access to Your Content section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_default_viewer_tls12_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.7] Cloudfront Distributions should enforce TLS 1.2 for the default viewer protocol"""
    cloudfront = session.client("cloudfront")
    # TLS 1.2 policies
    compliantMinimumProtocolVersions = [
        "TLSv1.2_2021",
        "TLSv1.2_2019",
        "TLSv1.2_2018"
    ]
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["ViewerCertificate"]["MinimumProtocolVersion"]) not in compliantMinimumProtocolVersions:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-tls12-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[CloudFront.7] Cloudfront Distributions should enforce TLS 1.2 for the default viewer protocol",
                "Description": f"CloudFront Distribution {distributionId} does not enforce a compliant TLS 1.2 minimum protocol for default viewer behavior. When you require HTTPS between viewers and your CloudFront distribution, you must choose a security policy, which determines the following settings: The minimum SSL/TLS protocol and ciphers that CloudFront uses to communicate with viewers. TLS 1.2 is more secure than the previous cryptographic protocols such as SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1. Essentially, TLS 1.2 keeps data being transferred across the network more secure. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Default TLS settings for CloudFront, refer to the Supported protocols and ciphers between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-tls12-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.7] Cloudfront Distributions should enforce TLS 1.2 for the default viewer protocol",
                "Description": f"CloudFront Distribution {distributionId} enforces a compliant TLS 1.2 minimum protocol for default viewer behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Default TLS settings for CloudFront, refer to the Supported protocols and ciphers between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_custom_origin_tls12_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.8] Cloudfront Distributions with Custom Origins should allow only TLSv1.2 protocols"""
    cloudfront = session.client("cloudfront")
    # Non compliant policies
    nonCompliantViewerCiphers = [
        "SSLv3",
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2"
    ]
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if not distro["DistributionConfig"]["Origins"]["Items"]:
            continue
        else:
            for orig in distro["DistributionConfig"]["Origins"]["Items"]:
                originId = orig["Id"]
                try:
                    customOriginCiphers = orig["CustomOriginConfig"]["OriginSslProtocols"]["Items"]
                    if any(x in customOriginCiphers for x in nonCompliantViewerCiphers):
                        # this is a failing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-tls12-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": distributionArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[CloudFront.8] Cloudfront Distributions with Custom Origins should allow only TLSv1.2 protocols",
                            "Description": f"CloudFront Origin {originId} for Distribution {distributionId} allows a non-TLSv1.2 cipher protocol. The minimum origin SSL protocol specifies the minimum TLS/SSL protocol that CloudFront can use when it establishes an HTTPS connection to your origin. Lower TLS protocols are less secure, so we recommend that you choose the latest TLS protocol that your origin supports. For more information see the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Values That You Specify When You Create or Update a Distribution section of the Amazon CloudFront Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginSSLProtocols",
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
                                "AssetService": "Amazon CloudFront",
                                "AssetComponent": "Distribution"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsCloudFrontDistribution",
                                    "Id": distributionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCloudFrontDistribution": {
                                            "DomainName": domainName,
                                            "Status": distStatus,
                                            "Origins": {
                                                "Items": [
                                                    {
                                                        "Id": originId
                                                    }
                                                ]
                                            }
                                        }
                                    }
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
                        # this is a passing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-tls12-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": distributionArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[CloudFront.8] Cloudfront Distributions with Custom Origins should allow only TLSv1.2 protocols",
                            "Description": f"CloudFront Origin {originId} for Distribution {distributionId} does not allow any non-TLSv1.2 cipher protocols.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Values That You Specify When You Create or Update a Distribution section of the Amazon CloudFront Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginSSLProtocols",
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
                                "AssetService": "Amazon CloudFront",
                                "AssetComponent": "Distribution"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsCloudFrontDistribution",
                                    "Id": distributionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCloudFrontDistribution": {
                                            "DomainName": domainName,
                                            "Status": distStatus,
                                            "Origins": {
                                                "Items": [
                                                    {
                                                        "Id": originId
                                                    }
                                                ]
                                            }
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
                except KeyError:
                    # KeyError exception means there is not a custom origin within the current iterated Origin
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-tls12-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CloudFront.8] Cloudfront Distributions with Custom Origins should allow only TLSv1.2 protocols",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} is not a custom origin and is thus not in scope for this check.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Values That You Specify When You Create or Update a Distribution section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginSSLProtocols",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
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

@registry.register_check("cloudfront")
def cloudfront_custom_origin_https_only_protcol_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.9] Cloudfront Distributions with Custom Origins should enforce HTTPS-only protocol policies"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if not distro["DistributionConfig"]["Origins"]["Items"]:
            continue
        else:
            for orig in distro["DistributionConfig"]["Origins"]["Items"]:
                originId = orig["Id"]
                try:
                    if str(orig["CustomOriginConfig"]["OriginProtocolPolicy"]) != "https-only":
                        # this is a failing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-https-only-protocol-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": distributionArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[CloudFront.9] Cloudfront Distributions with Custom Origins should enforce HTTPS-only protocol policies",
                            "Description": f"CloudFront Origin {originId} for Distribution {distributionId} does not enforce a HTTPS-only protocol policy. You can require HTTPS for communication between CloudFront and your origin when you specify HTTPS Only CloudFront uses only HTTPS to communicate with your custom origin. For more information see the remediation section.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Requiring HTTPS for communication between CloudFront and your custom origin section of the Amazon CloudFront Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
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
                                "AssetService": "Amazon CloudFront",
                                "AssetComponent": "Distribution"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsCloudFrontDistribution",
                                    "Id": distributionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCloudFrontDistribution": {
                                            "DomainName": domainName,
                                            "Status": distStatus,
                                            "Origins": {
                                                "Items": [
                                                    {
                                                        "Id": originId
                                                    }
                                                ]
                                            }
                                        }
                                    }
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
                        # this is a passing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-https-only-protocol-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": distributionArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[CloudFront.9] Cloudfront Distributions with Custom Origins should enforce HTTPS-only protocol policies",
                            "Description": f"CloudFront Origin {originId} for Distribution {distributionId} enforces a HTTPS-only protocol policy.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Requiring HTTPS for communication between CloudFront and your custom origin section of the Amazon CloudFront Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
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
                                "AssetService": "Amazon CloudFront",
                                "AssetComponent": "Distribution"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsCloudFrontDistribution",
                                    "Id": distributionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCloudFrontDistribution": {
                                            "DomainName": domainName,
                                            "Status": distStatus,
                                            "Origins": {
                                                "Items": [
                                                    {
                                                        "Id": originId
                                                    }
                                                ]
                                            }
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
                except KeyError:
                    # KeyError exception means there is not a custom origin within the current iterated Origin
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/{originId}/cloudfront-custom-origin-https-only-protocol-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CloudFront.9] Cloudfront Distributions with Custom Origins should enforce HTTPS-only protocol policies",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} is not a custom origin and is thus not in scope for this check.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Custom Origin TLS settings for CloudFront, refer to the Requiring HTTPS for communication between CloudFront and your custom origin section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
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

@registry.register_check("cloudfront")
def cloudfront_default_viewer_https_sni_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.10] Cloudfront Distributions should enforce Server Name Indication (SNI) to serve HTTPS requests"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["ViewerCertificate"]["SSLSupportMethod"]) != "sni-only":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-https-sni-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CloudFront.10] Cloudfront Distributions should enforce Server Name Indication (SNI) to serve HTTPS requests",
                "Description": f"CloudFront Distribution {distributionId} does not enforce Server Name Indication (SNI) for default viewer HTTPS connectivity behavior. SNI is an extension to the TLS protocol that is supported by browsers and clients released after 2010. If you configure CloudFront to serve HTTPS requests using SNI, CloudFront associates your alternate domain name with an IP address for each edge location. When a viewer submits an HTTPS request for your content, DNS routes the request to the IP address for the correct edge location. The IP address to your domain name is determined during the SSL/TLS handshake negotiation; the IP address isn't dedicated to your distribution. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your CloudFront distributions to use SNI to serve HTTPS requests refer to the Using SNI to Serve HTTPS Requests (works for Most Clients) section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-https-dedicated-ip-or-sni.html#cnames-https-sni",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-https-sni-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.10] Cloudfront Distributions should enforce Server Name Indication (SNI) to serve HTTPS requests",
                "Description": f"CloudFront Distribution {distributionId} enforces Server Name Indication (SNI) for default viewer HTTPS connectivity behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your CloudFront distributions to use SNI to serve HTTPS requests refer to the Using SNI to Serve HTTPS Requests (works for Most Clients) section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-https-dedicated-ip-or-sni.html#cnames-https-sni",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_distro_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.11] Cloudfront Distributions should have logging enabled"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["Logging"]["Enabled"]) == "False":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-distro-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CloudFront.11] Cloudfront Distributions should have logging enabled",
                "Description": f"CloudFront Distribution {distributionId} does not have logging enabled. CloudFront standard logs provide detailed records about every request that's made to a distribution. These logs are useful for many scenarios, including security and access audits. CloudFront standard logs are delivered to the Amazon S3 bucket of your choice. CloudFront doesn't charge for standard logs, though you incur Amazon S3 charges for storing and accessing the log files. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your CloudFront distributions to log requests refer to the CloudFront logging section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/logging.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-distro-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.11] Cloudfront Distributions should have logging enabled",
                "Description": f"CloudFront Distribution {distributionId} has logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your CloudFront distributions to log requests refer to the CloudFront logging section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/logging.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_distro_default_root_object_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.12] Cloudfront Distributions should have a default root object configured"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["DefaultRootObject"]) == "":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-distro-default-root-object-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[CloudFront.12] Cloudfront Distributions should have a default root object configured",
                "Description": f"CloudFront Distribution {distributionId} does not have a default root object configured. A user might sometimes request the distribution's root URL instead of an object in the distribution. When this happens, specifying a default root object can help you to avoid exposing the contents of your web distribution. If you define a default root object, an end-user request for a subdirectory of your distribution does not return the default root object. For example, suppose index.html is your default root object and that CloudFront receives an end-user request for the install directory under your CloudFront distribution: 'https://d111111abcdef8.cloudfront.net/install/' CloudFront does not return the default root object even if a copy of index.html appears in the install directory. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For detailed instructions on how to specify a default root object for your distribution refer to the How to specify a default root object section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DefaultRootObject.html#DefaultRootObjectHowToDefine",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-distro-default-root-object-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.12] Cloudfront Distributions should have a default root object configured",
                "Description": f"CloudFront Distribution {distributionId} has a default root object configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For detailed instructions on how to specify a default root object for your distribution refer to the How to specify a default root object section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DefaultRootObject.html#DefaultRootObjectHowToDefine",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_default_viewer_https_only_protcol_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.13] Cloudfront Distributions should enforce should enforce HTTPS-only for the default viewer protocol"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if str(distro["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"]) != "https-only":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-https-only-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[CloudFront.13] Cloudfront Distributions should enforce should enforce HTTPS-only for the default viewer protocol",
                "Description": f"CloudFront Distribution {distributionId} does not enforce HTTPS-only connections for the default viewer protocol. You can configure one or more cache behaviors in your CloudFront distribution to require HTTPS for communication between viewers and CloudFront. With HTTPS Only viewers can access your content only if they're using HTTPS. If a viewer sends an HTTP request instead of an HTTPS request, CloudFront returns HTTP status code 403 (Forbidden) and does not return the object. For more information see the remediation section.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For detailed instructions on how to specify HTTPS-only connections for your distribution refer to the Requiring HTTPS for communication between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
                            }
                        }
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-default-viewer-https-only-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CloudFront.13] Cloudfront Distributions should enforce should enforce HTTPS-only for the default viewer protocol",
                "Description": f"CloudFront Distribution {distributionId} enforces HTTPS-only connections for the default viewer protocol.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For detailed instructions on how to specify HTTPS-only connections for your distribution refer to the Requiring HTTPS for communication between viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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

@registry.register_check("cloudfront")
def cloudfront_s3_origin_oai_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.14] Cloudfront Distributions with S3 Origins should have origin access identity enabled"""
    cloudfront = session.client("cloudfront")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate_distributions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Get check specific metadata
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        if not distro["DistributionConfig"]["Origins"]["Items"]:
            continue
        else:
            for orig in distro["DistributionConfig"]["Origins"]["Items"]:
                originId = orig["Id"]
                try:
                    if not orig["S3OriginConfig"]["OriginAccessIdentity"]:
                        s3OaiEnabled = False
                    else:
                        s3OaiEnabled = True
                except KeyError:
                    s3OaiEnabled = True
                
                # this is a failing check
                if s3OaiEnabled is False:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{distributionArn}/{originId}/cloudfront-s3-origin-origin-access-identity-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[CloudFront.14] Cloudfront Distributions with S3 Origins should have origin access identity enabled",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} does not have an origin access identity enabled. CloudFront OAI prevents users from accessing S3 bucket content directly. When users access an S3 bucket directly, they effectively bypass the CloudFront distribution and any permissions that are applied to the underlying S3 bucket content. For more information see the remediation section.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For detailed remediation instructions refer to the Creating a CloudFront OAI and adding it to your distribution section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html#private-content-creating-oai",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
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
                                "ISO 27001:2013 A.14.1.3"
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
                        "Id": f"{distributionArn}/{originId}/cloudfront-s3-origin-origin-access-identity-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": distributionArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CloudFront.14] Cloudfront Distributions with S3 Origins should have origin access identity enabled",
                        "Description": f"CloudFront Origin {originId} for Distribution {distributionId} has an origin access identity enabled or is not associated with an Amazon S3 bucket.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For detailed remediation instructions refer to the Creating a CloudFront OAI and adding it to your distribution section of the Amazon CloudFront Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html#private-content-creating-oai",
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
                            "AssetService": "Amazon CloudFront",
                            "AssetComponent": "Distribution"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": domainName,
                                        "Status": distStatus,
                                        "Origins": {
                                            "Items": [
                                                {
                                                    "Id": originId
                                                }
                                            ]
                                        }
                                    }
                                }
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
                                "ISO 27001:2013 A.14.1.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding

@registry.register_check("cloudfront")
def cloudfront_shodan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.14] CloudFront Distributions should be monitored for being indexed by Shodan"""
    shodanApiKey = get_shodan_api_key(cache)
    # ISO Time
    iso8601time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for dist in paginate_distributions(cache, session):
        if shodanApiKey is None:
            continue
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(dist,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        domainName = dist["DomainName"]
        distStatus = dist["Status"]
        # Use Google DNS to resolve
        cfDomainIp = google_dns_resolver(domainName)
        if cfDomainIp is None:
            continue
        # check if IP indexed by Shodan
        r = requests.get(url=f"{SHODAN_HOSTS_URL}{cfDomainIp}?key={shodanApiKey}").json()
        if str(r) == "{'error': 'No information available for that IP.'}":
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/{domainName}/cloudfront-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{distributionArn}/{domainName}/cloudfront-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Title": "[CloudFront.14] CloudFront Distributions should be monitored for being indexed by Shodan",
                "Description": f"CloudFront Distribution {distributionId} has not been indexed by Shodan.",
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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
                "Distribution": dist,
                "Shodan": r
            }
            assetJson = json.dumps(assetPayload,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/{domainName}/cloudfront-shodan-index-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{distributionArn}/{domainName}/cloudfront-shodan-index-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Effects/Data Exposure"],
                "CreatedAt": iso8601time,
                "UpdatedAt": iso8601time,
                "Severity": {"Label": "MEDIUM"},
                "Title": "[CloudFront.14] CloudFront Distributions should be monitored for being indexed by Shodan",
                "Description": f"CloudFront Distribution {distributionId} has been indexed by Shodan on IP address {cfDomainIp} - resolved from DNS name {domainName}. Shodan is an 'internet search engine' which continuously crawls and scans across the entire internet to capture host, geolocation, TLS, and running service information. Shodan is a popular tool used by blue teams, security researchers and adversaries alike. Having your asset indexed on Shodan, depending on its configuration, may increase its risk of unauthorized access and further compromise. Review your configuration and refer to the Shodan URL in the remediation section to take action to reduce your exposure and harden your host.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about the information that Shodan indexed on your host refer to the URL in the remediation section.",
                        "Url": f"{SHODAN_HOSTS_URL}{cfDomainIp}"
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
                    "AssetService": "Amazon CloudFront",
                    "AssetComponent": "Distribution"
                },
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCloudFrontDistribution": {
                                "DomainName": domainName,
                                "Status": distStatus
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