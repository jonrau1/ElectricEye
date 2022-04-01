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
    """[CloudFront.1] Trusted signers should have key pairs"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for dist in paginate(cache):
        distributionId = dist["Id"]
        distributionArn = dist["ARN"]
        # Get deeper details
        distro = cloudfront.get_distribution(Id=distributionId)["Distribution"]
        print(json.dumps(distro,indent=4,default=str))


        distribution = cloudfront.get_distribution(Id=distributionId)
        # Check specific metadata
        activeTrustedSigners = distribution["Distribution"]["ActiveTrustedSigners"]["Enabled"]
        distributionArn = distribution["Distribution"]["ARN"]
        
        if not activeTrustedSigners:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{distributionArn}/cloudfront-active-trusted-signers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
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
                "Id": f"{distributionArn}/cloudfront-active-trusted-signers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": distributionArn,
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



## TODO: NEXT