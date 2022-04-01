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
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                        "ProductFields": {"Product Name": "ElectricEye"},
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

@registry.register_check("cloudfront")
def cloudfront_default_viewer_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.3] Cloudfront Distributions should not use the default Viewer certificate"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
def cloudfront_georestriction_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.4] Cloudfront Distributions should have a Georestriction configured"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
def cloudfront_field_level_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.5] Cloudfront Distributions should implement Field-Level Encryption in default cache behavior"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudfront")
def cloudfront_waf_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.6] Cloudfront Distributions should use a Web Application Firewall"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudfront")
def cloudfront_default_viewer_tls12_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.7] Cloudfront Distributions should enforce TLS 1.2 for the default viewer protocol"""
    # TLS 1.2 policies
    compliantMinimumProtocolVersions = [
        "TLSv1.2_2021",
        "TLSv1.2_2019",
        "TLSv1.2_2018"
    ]
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
def cloudfront_custom_origin_tls12_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.8] Cloudfront Distributions with Custom Origins should allow only TLSv1.2 protocols"""
    # Non compliant policies
    nonCompliantViewerCiphers = [
        "SSLv3",
        "TLSv1",
        "TLSv1.1",
        "TLSv1.2"
    ]
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.DS-2",
                                    "NIST SP 800-53 SC-8",
                                    "NIST SP 800-53 SC-11",
                                    "NIST SP 800-53 SC-12",
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.DS-2",
                                    "NIST SP 800-53 SC-8",
                                    "NIST SP 800-53 SC-11",
                                    "NIST SP 800-53 SC-12",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                                "NIST CSF PR.DS-2",
                                "NIST SP 800-53 SC-8",
                                "NIST SP 800-53 SC-11",
                                "NIST SP 800-53 SC-12",
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
def cloudfront_custom_origin_https_only_protcol_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.9] Cloudfront Distributions with Custom Origins should enforce HTTPS-only protocol policies"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.DS-2",
                                    "NIST SP 800-53 SC-8",
                                    "NIST SP 800-53 SC-11",
                                    "NIST SP 800-53 SC-12",
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                                    "NIST CSF PR.DS-2",
                                    "NIST SP 800-53 SC-8",
                                    "NIST SP 800-53 SC-11",
                                    "NIST SP 800-53 SC-12",
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
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                                "NIST CSF PR.DS-2",
                                "NIST SP 800-53 SC-8",
                                "NIST SP 800-53 SC-11",
                                "NIST SP 800-53 SC-12",
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
def cloudfront_default_viewer_tls12_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.10] Cloudfront Distributions should enforce Server Name Indication (SNI) to serve HTTPS requests"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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
                "ProductFields": {"Product Name": "ElectricEye"},
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
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
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

## TODO: NEXT