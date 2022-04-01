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
import json
import boto3
from check_register import CheckRegister

registry = CheckRegister()

cloudfront = boto3.client("cloudfront")

def paginate(cache):
    itemList = []
    response = cache.get("items")
    if response:
        return response
    paginator = cloudfront.get_paginator("list_distributions")
    if paginator:
        for page in paginator.paginate():
            for items in page["DistributionList"]["Items"]:
                itemList.append(items)
        cache["items"] = itemList
        return cache["items"]

@registry.register_check("cloudfront")
def cloudfront_active_trusted_signers_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.1] Cloudfront Distributions with active Trusted Signers should use Key Pairs"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
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
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF ID.AM-2",
                                "NIST SP 800-53 CM-8",
                                "NIST SP 800-53 PM-5",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF ID.AM-2",
                                "NIST SP 800-53 CM-8",
                                "NIST SP 800-53 PM-5",
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
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCloudFrontDistribution",
                        "Id": distributionArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.AM-2",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PM-5",
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
def cloudfront_origin_shield_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.2] Cloudfront Distributions Origins should have Origin Shield enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
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
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF ID.BE-5",
                                "NIST CSF PR.PT-5",
                                "NIST SP 800-53 CP-2",
                                "NIST SP 800-53 CP-11",
                                "NIST SP 800-53 SA-13",
                                "NIST SP 800-53 SA14",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distributionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF ID.BE-5",
                                "NIST CSF PR.PT-5",
                                "NIST SP 800-53 CP-2",
                                "NIST SP 800-53 CP-11",
                                "NIST SP 800-53 SA-13",
                                "NIST SP 800-53 SA14",
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

## TODO: NEXT