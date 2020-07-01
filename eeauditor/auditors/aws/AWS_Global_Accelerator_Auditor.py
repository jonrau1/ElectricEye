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
globalaccelerator = boto3.client("globalaccelerator")


@registry.register_check("globalaccelerator")
def unhealthy_endpoint_group_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    paginator = globalaccelerator.get_paginator("list_accelerators")
    response_iterator = paginator.paginate()
    accelerators = accumulate_paged_results(
        page_iterator=response_iterator, key="Accelerators"
    )
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accelerator in accelerators["Accelerators"]:
        paginator = globalaccelerator.get_paginator("list_listeners")
        response_iterator = paginator.paginate(
            AcceleratorArn=accelerator["AcceleratorArn"]
        )
        listeners = accumulate_paged_results(
            page_iterator=response_iterator, key="Listeners"
        )
        for listener in listeners["Listeners"]:
            paginator = globalaccelerator.get_paginator("list_endpoint_groups")
            response_iterator = paginator.paginate(ListenerArn=listener["ListenerArn"])
            endpointGroups = accumulate_paged_results(
                page_iterator=response_iterator, key="EndpointGroups"
            )
            for endpointGroup in endpointGroups["EndpointGroups"]:
                for description in endpointGroup["EndpointDescriptions"]:
                    endpointId = description["EndpointId"]
                    health = description["HealthState"]
                    generatorUuid = str(uuid.uuid4())
                    if health != "UNHEALTHY":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": awsAccountId + "/unhealthy-endpoint-group-check",
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
                            "Title": "[GlobalAccelerator.1] Endpoint should not be unhealthy",
                            "Description": "Endpoint id "
                            + endpointId
                            + " is not unhealthy.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on the health of endpoints refer to the Endpoints in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoints.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsGlobalAcceleratorEndpoint",
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
                            "Id": awsAccountId + "/unhealthy-endpoint-group-check",
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
                            "Title": "[GlobalAccelerator.1] Endpoint should not be unhealthy",
                            "Description": "Endpoint id "
                            + endpointId
                            + " is unhealthy.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on the health of endpoints refer to the Endpoints in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/about-endpoints.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsGlobalAcceleratorEndpoint",
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


@registry.register_check("globalaccelerator")
def flow_logs_enabled_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    paginator = globalaccelerator.get_paginator("list_accelerators")
    response_iterator = paginator.paginate()
    accelerators = accumulate_paged_results(
        page_iterator=response_iterator, key="Accelerators"
    )
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accelerator in accelerators["Accelerators"]:
        acceleratorAttributes = globalaccelerator.describe_accelerator_attributes(
            AcceleratorArn=accelerator["AcceleratorArn"]
        )
        acceleratorName = accelerator["Name"]
        generatorUuid = str(uuid.uuid4())
        loggingEnabled = acceleratorAttributes["AcceleratorAttributes"][
            "FlowLogsEnabled"
        ]
        if loggingEnabled:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/access-logging-enabled-check",
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
                "Title": "[GlobalAccelerator.2] Accelerator should have flow logs enabled",
                "Description": "Accelerator "
                + acceleratorName
                + " has flow logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on accelerator flow logs refer to the Flow logs in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
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
                "Id": awsAccountId + "/access-logging-enabled-check",
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
                "Title": "[GlobalAccelerator.2] Accelerator should have flow logs enabled",
                "Description": "Accelerator "
                + acceleratorName
                + " does not have flow logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on accelerator flow logs refer to the Flow logs in AWS Global Accelerator section of the AWS Global Accelerator Developer Guide",
                        "Url": "https://docs.aws.amazon.com/global-accelerator/latest/dg/monitoring-global-accelerator.flow-logs.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
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
