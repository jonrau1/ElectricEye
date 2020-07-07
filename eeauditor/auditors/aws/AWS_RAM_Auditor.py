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
ram = boto3.client("ram")


def get_resource_shares(cache):
    response = cache.get("get_resource_shares")
    if response:
        return response
    paginator = ram.get_paginator("get_resource_shares")
    response_iterator = paginator.paginate(resourceOwner="SELF")
    results = accumulate_paged_results(
        page_iterator=response_iterator, key="resourceShares"
    )
    cache["get_resource_shares"] = results
    return cache["get_resource_shares"]


@registry.register_check("ram")
def ram_resource_shares_status_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    responses = []
    responses.append(get_resource_shares(cache))
    paginator = ram.get_paginator("get_resource_shares")
    response_iterator = paginator.paginate(resourceOwner="OTHER-ACCOUNTS")
    responses.append(
        accumulate_paged_results(page_iterator=response_iterator, key="resourceShares")
    )
    for response in responses:
        resourceShares = response["resourceShares"]
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for resourceShare in resourceShares:
            resourceshareArn = resourceShare["resourceShareArn"]
            status = resourceShare["status"]
            shareName = resourceShare["name"]
            generatorUuid = str(uuid.uuid4())
            if status != "FAILED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/ram-resource-shares-status-check",
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
                    "Title": "[RAM.1] Resource share should not have a failed status",
                    "Description": "Resource share "
                    + shareName
                    + " does not have a failed status.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on resource share statuses refer to the Viewing Resource Shares section of the AWS Resource Access Manager User Guide",
                            "Url": "https://docs.aws.amazon.com/ram/latest/userguide/working-with-shared.html#working-with-shared-view-rs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsResourceAccessManagerShare",
                            "Id": resourceshareArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "PASSED",},
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/ram-resource-shares-status-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[RAM.1] Resource share should not have a failed status",
                    "Description": "Resource share "
                    + shareName
                    + " has a failed status.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on resource share statuses refer to the Viewing Resource Shares section of the AWS Resource Access Manager User Guide",
                            "Url": "https://docs.aws.amazon.com/ram/latest/userguide/working-with-shared.html#working-with-shared-view-rs",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsResourceAccessManagerShare",
                            "Id": resourceshareArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "FAILED"},
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding


@registry.register_check("ram")
def ram_allow_external_principals_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = get_resource_shares(cache)
    resourceShares = response["resourceShares"]
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for resourceShare in resourceShares:
        allowExternalPrincipals = resourceShare["allowExternalPrincipals"]
        shareName = resourceShare["name"]
        generatorUuid = str(uuid.uuid4())
        if not allowExternalPrincipals:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/ram-allow-external-principals-check",
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
                "Title": "[RAM.2] Resource share should not allow external principals",
                "Description": "Resource share "
                + shareName
                + " does not allow external principals.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on resource share external principals refer to the How AWS RAM Works with IAM section of the AWS Resource Access Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/ram/latest/userguide/iam-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsResourceAccessManagerShare",
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/ram-allow-external-principals-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": generatorUuid,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[RAM.2] Resource share should not allow external principals",
                "Description": "Resource share "
                + shareName
                + " allows external principals.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on resource share external principals refer to the How AWS RAM Works with IAM section of the AWS Resource Access Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/ram/latest/userguide/iam-policies.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsResourceAccessManagerShare",
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
