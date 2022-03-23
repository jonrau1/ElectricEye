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
from dateutil import parser
import uuid
import boto3
from check_register import CheckRegister, accumulate_paged_results

registry = CheckRegister()
cloudfront = boto3.client("cloudfront")

paginator = cloudfront.get_paginator("list_distributions")
response_iterator = paginator.paginate()
results = {"DistributionList": {"Items": []}}
for page in response_iterator:
    page_vals = page["DistributionList"].get("Items", [])
    results["DistributionList"]["Items"].extend(iter(page_vals))

@registry.register_check("cloudfront")
def cloudfront_active_trusted_signers_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.1] Trusted signers should have key pairs"""
    
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            activeTrustedSigners = distribution["Distribution"]["ActiveTrustedSigners"]["Enabled"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not activeTrustedSigners:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-active-trusted-signers-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.1] Trusted signers should have key pairs",
                    "Description": "Distribution "
                    + distributionId
                    + " has trusted signers without key pairs.",
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
                    "Id": awsAccountId + "/cloudfront-active-trusted-signers-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudFront.1] Trusted signers should have key pairs",
                    "Description": "Distribution "
                    + distributionId
                    + " has trusted signers with key pairs.",
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
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
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
                            "ISO 27001:2013 A.12.5.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_origin_shield_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.2] Distributions should have Origin Shield enabled"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            originShield = distribution["Distribution"]["DistributionConfig"]["Origins"]["Items"]["OriginShield"]["Enabled"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not originShield:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-originshield-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.2] Distributions should have Origin Shield enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have Origin Shield enabled.",
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
                            "ISO 27001:2013 A.17.2.1",                            
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-origin-shield-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CloudFront.2] Distributions should have Origin Shield enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " has Origin Shield enabled.",
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
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
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
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_default_viewer_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.3] Distributions should have a Default Viewer certificate in place"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            defaultViewer = distribution["Distribution"]["DistributionConfig"]["ViewerCertificate": {"CloudFrontDefaultCertificate": True}]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not defaultViewer:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-defaultviewer-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.3] Distributions should have a Default Viewer certificate in place",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have Default Viewer certificate in place.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Default Viewer certificates for CloudFront, refer to the Requiring HTTPS for Communication Between Viewers and CloudFront section of the Amazon CloudFront Developer Guide",
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-defaultviewer-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.3] Distributions should have a Default Viewer certificate in place",
                    "Description": "Distribution "
                    + distributionId
                    + " has Default Viewer certificate in place.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Default Viewer certificates for CloudFront, refer to the Requiring HTTPS for Communication Between Viewers and CloudFront section of the Amazon CloudFront Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCloudFrontDistribution",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_georestriction_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.4] Distributions should have Geo Ristriction in place"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            geoRestriction = distribution["Distribution"]["DistributionConfig"]["Restrictions"]["GeoRestriction"]["RestrictionType"]["CloudFrontDefaultCertificate": "blacklist"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not geoRestriction:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-geo-restriction-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.4] Distributions should have Geo Ristriction in place",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have Geo Restriction in place.",
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-geo-restriction-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.4] Distributions should have Geo Ristriction in place",
                    "Description": "Distribution "
                    + distributionId
                    + " has Geo Restriction in place.",
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
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_field_level_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.5] Distributions should have Field-Level Encryption in place"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            fieldLevelEncryption = distribution["Distribution"]["DistributionConfig"]["DefaultCacheBehavior"]["FieldLevelEncryptionId": "string"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not fieldLevelEncryption:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-field-level-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.5] Distributions should have Field-Level Encryption in place",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have Field Level Encryption in place.",
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
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-field-level-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.5] Distributions should have Field-Level Encryption in place",
                    "Description": "Distribution "
                    + distributionId
                    + " does have Field-Level Encryption in place.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Field Level Encryption for CloudFront, refer to the Using Field-Level Encryption to Help Protect Sensitive Data section of the Amazon CloudFront Developer Guide",
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
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_waf_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.6] Distributions should have WAF enabled"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            wafEnabled = distribution["Distribution"]["DistributionConfig"]["WebACLId": "string"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not wafEnabled:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-waf-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.6] Distributions should have WAF enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have WAF enabled.",
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
                            "ISO 27001:2013 A.16.1.4",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-waf-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.6] Distributions should have WAF enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " does has WAF enabled.",
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
                            "ISO 27001:2013 A.16.1.4",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_default_tls_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.7] Distributions should have Default TLS enabled"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            defaultTls = distribution["Distribution"]["DistributionConfig"]["MinimumProtocolVersion": "TLSv1"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not defaultTls:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-default-tls-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.7] Distributions should have Default TLS enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " does not have Default TLS enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Default TLS settings for CloudFront, refer to the Creating, Updating, and Deleting Distributions section of the Amazon CloudFront Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy",
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
                            "ISO 27001:2013 A.14.1.3",                            
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-default-tls-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.7] Distributions should have Default TLS enabled",
                    "Description": "Distribution "
                    + distributionId
                    + " does have Default TLS enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Default TLS settings for CloudFront, refer to the Creating, Updating, and Deleting Distributions section of the Amazon CloudFront Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValues-security-policy",
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
                            "ISO 27001:2013 A.14.1.3",                            
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("cloudfront")
def cloudfront_custom_origin_tls_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CloudFront.8] Distributions using Custom Origins should be using TLSv1.2"""
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            customOriginTls = distribution["Distribution"]["DistributionConfig"]["Origins"]["Items"]["Origins"]["CustomOriginConfig"]["OriginSslProtocols"]["Items": "TLSv1.2"]
            distributionArn = distribution["Distribution"]["ARN"]
            generatorUuid = str(uuid.uuid4())
            if not customOriginTls:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-custom-origin-tls-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.8] Distributions using Custom Origins should be using TLSv1.2",
                    "Description": "Distribution "
                    + distributionId
                    + " has Custom Origins not using TLSv1.2.",
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
                            "ISO 27001:2013 A.14.1.3",                            
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/cloudfront-custom-origin-tls-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[CloudFront.8] Distributions using Custom Origins should be using TLSv1.2",
                    "Description": "Distribution "
                    + distributionId
                    + " has Custom Origins using TLSv1.2.",
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
                            "ISO 27001:2013 A.14.1.3",                            
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)