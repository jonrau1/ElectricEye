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


@registry.register_check("cloudfront")
def cloudfront_active_trusted_signers_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    paginator = cloudfront.get_paginator("list_distributions")
    response_iterator = paginator.paginate()
    results = {"DistributionList": {"Items": []}}
    for page in response_iterator:
        page_vals = page["DistributionList"].get("Items", [])
        results["DistributionList"]["Items"].extend(iter(page_vals))
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for distributionItem in results["DistributionList"]["Items"]:
        distributionId = distributionItem["Id"]
        distribution = cloudfront.get_distribution(Id=distributionId)
        try:
            activeTrustedSigners = distribution["Distribution"]["ActiveTrustedSigners"][
                "Enabled"
            ]
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
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "FAILED"},
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
                    "Compliance": {"Status": "PASSED",},
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)
