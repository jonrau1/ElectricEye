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
                    "ProductFields": {"Product Name": "Day2SecurityBot"},
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
                    "ProductFields": {"Product Name": "DaySecurityBot"},
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
