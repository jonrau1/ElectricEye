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
import uuid
from check_register import CheckRegister, accumulate_paged_results
import base64
import json

registry = CheckRegister()

@registry.register_check("globalaccelerator")
def unhealthy_endpoint_group_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GlobalAccelerator.1] Endpoint should not be unhealthy"""
    if awsPartition == "aws":
        globalaccelerator = session.client("globalaccelerator", region_name="us-west-2")
    else:
        globalaccelerator = session.client("globalaccelerator")

    paginator = globalaccelerator.get_paginator("list_accelerators")
    response_iterator = paginator.paginate()
    accelerators = accumulate_paged_results(
        page_iterator=response_iterator, key="Accelerators"
    )
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accelerator in accelerators["Accelerators"]:
        paginator = globalaccelerator.get_paginator("list_listeners")
        acceleratorArn = accelerator["AcceleratorArn"]
        response_iterator = paginator.paginate(
            AcceleratorArn=acceleratorArn
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
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(endpointGroup,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                endpointGroupArn = endpointGroup["EndpointGroupArn"]
                for description in endpointGroup["EndpointDescriptions"]:
                    endpointId = description["EndpointId"]
                    health = description["HealthState"]
                    generatorUuid = str(uuid.uuid4())
                    if health != "UNHEALTHY":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": endpointGroupArn + "/unhealthy-endpoint-group-check",
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
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": "aws-global",
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Amazon Global Accelerator",
                                "AssetComponent": "Endpoint"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsGlobalAcceleratorEndpoint",
                                    "Id": endpointGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-4",
                                    "NIST CSF V1.1 DE.DP-4",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-2",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 CP-2",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 RA-3",
                                    "NIST SP 800-53 Rev. 4 RA-5",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "AICPA TSC CC7.3",
                                    "ISO 27001:2013 A.16.1.2",
                                    "ISO 27001:2013 A.16.1.3",
                                    "ISO 27001:2013 A.16.1.4"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": endpointGroupArn + "/unhealthy-endpoint-group-check",
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
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": "aws-global",
                                "AssetDetails": assetB64,
                                "AssetClass": "Networking",
                                "AssetService": "Amazon Global Accelerator",
                                "AssetComponent": "Endpoint"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsGlobalAcceleratorEndpoint",
                                    "Id": endpointGroupArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.AE-4",
                                    "NIST CSF V1.1 DE.DP-4",
                                    "NIST SP 800-53 Rev. 4 AU-6",
                                    "NIST SP 800-53 Rev. 4 CA-2",
                                    "NIST SP 800-53 Rev. 4 CA-7",
                                    "NIST SP 800-53 Rev. 4 CP-2",
                                    "NIST SP 800-53 Rev. 4 IR-4",
                                    "NIST SP 800-53 Rev. 4 RA-3",
                                    "NIST SP 800-53 Rev. 4 RA-5",
                                    "NIST SP 800-53 Rev. 4 SI-4",
                                    "AICPA TSC CC7.2",
                                    "AICPA TSC CC7.3",
                                    "ISO 27001:2013 A.16.1.2",
                                    "ISO 27001:2013 A.16.1.3",
                                    "ISO 27001:2013 A.16.1.4"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding

@registry.register_check("globalaccelerator")
def flow_logs_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[GlobalAccelerator.2] Accelerator should have flow logs enabled"""
    if awsPartition == "aws":
        globalaccelerator = session.client("globalaccelerator", region_name="us-west-2")
    else:
        globalaccelerator = session.client("globalaccelerator")

    paginator = globalaccelerator.get_paginator("list_accelerators")
    response_iterator = paginator.paginate()
    accelerators = accumulate_paged_results(
        page_iterator=response_iterator, key="Accelerators"
    )
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for accelerator in accelerators["Accelerators"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(accelerator,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        acceleratorArn = accelerator["AcceleratorArn"]
        acceleratorAttributes = globalaccelerator.describe_accelerator_attributes(
            AcceleratorArn=acceleratorArn
        )
        acceleratorName = accelerator["Name"]
        generatorUuid = str(uuid.uuid4())
        loggingEnabled = acceleratorAttributes["AcceleratorAttributes"][
            "FlowLogsEnabled"
        ]
        if loggingEnabled:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": acceleratorArn + "/access-logging-enabled-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": "aws-global",
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": acceleratorArn + "/access-logging-enabled-check",
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
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": "aws-global",
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Global Accelerator",
                    "AssetComponent": "Accelerator"
                },
                "Resources": [
                    {
                        "Type": "AwsGlobalAcceleratorAccelerator",
                        "Id": acceleratorArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding