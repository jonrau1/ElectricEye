# This file is part of ElectricEye.

# ElectricEye is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# ElectricEye is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with ElectricEye.
# If not, see https://github.com/jonrau1/ElectricEye/blob/master/LICENSE.

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
def cloudfront_active_trusted_signers_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
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
def cloudfront_origin_shield_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    
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
                    "Title": "[CloudFront.1] Distributions should have Origin Shield enabled",
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
                    "Title": "[CloudFront.1] Distributions should have Origin Shield enabled",
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
def cloudfront_default_viewer_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    
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
                    "Title": "[CloudFront.1] Distributions should have a Default Viewer certificate in place",
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
                    "Title": "[CloudFront.1] Distributions should have a Default Viewer certificate in place",
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