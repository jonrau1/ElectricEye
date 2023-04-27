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
from check_register import CheckRegister

registry = CheckRegister()

def get_hosted_zones(cache, session):
    route53 = session.client("route53")
    zones = []
    response = cache.get("get_hosted_zones")
    if response:
        return response
    paginator = route53.get_paginator('list_hosted_zones')
    if paginator:
        for page in paginator.paginate():
            for hz in page["HostedZones"]:
                zones.append(hz)
        cache["get_hosted_zones"] = zones
        return cache["get_hosted_zones"]
    
@registry.register_check("route53")
def route53_hosted_zone_query_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53.1] Route53 Hosted Zones should have query logging configured"""
    route53 = session.client("route53")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for zone in get_hosted_zones(cache, session):
        hzId = zone["Id"]
        hzName = zone["Name"]
        hzArn = f"arn:aws:route53:::hostedzone/{hzName}"
        hzType = str(zone["Config"]["PrivateZone"])
        # check specific metadata
        r = route53.list_query_logging_configs(HostedZoneId=hzId)["QueryLoggingConfigs"]
        # empty lists return mean there is not a configuration
        if not r:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{hzArn}/route53-query-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": hzArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Route53.1] Route53 Hosted Zones should have query logging configured",
                "Description": f"Route53 Hosted Zone {hzId} named {hzName} does not have query logging configured. Query logs contain only the queries that DNS resolvers forward to Route 53. If a DNS resolver has already cached the response to a query (such as the IP address for a load balancer for example.com), the resolver will continue to return the cached response without forwarding the query to Route 53 until the TTL for the corresponding record expires. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Route53 query logging and how to configure it refer to the Public DNS query logging section of the Amazon Route53 Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Route53",
                    "AssetType": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hzArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": hzId,
                                "Name": hzName,
                                "PrivateZone": hzType
                            }
                        }
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
                        "ISO 27001:2013 A.16.1.7"
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
                "Id": f"{hzArn}/route53-query-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": hzArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53.1] Route53 Hosted Zones should have query logging configured",
                "Description": f"Route53 Hosted Zone {hzId} named {hzName} has query logging configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Route53 query logging and how to configure it refer to the Public DNS query logging section of the Amazon Route53 Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Route53",
                    "AssetType": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hzArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": hzId,
                                "Name": hzName,
                                "PrivateZone": hzType
                            }
                        }
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("route53")
def route53_hosted_zone_traffic_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53.2] Route53 Hosted Zones should have traffic policies configured"""
    route53 = session.client("route53")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for zone in get_hosted_zones(cache, session):
        hzId = zone["Id"]
        hzName = zone["Name"]
        hzArn = f"arn:aws:route53:::hostedzone/{hzName}"
        hzType = str(zone["Config"]["PrivateZone"])
        # check specific metadata
        r = route53.list_traffic_policy_instances_by_hosted_zone(HostedZoneId=hzId)["TrafficPolicyInstances"]
        # empty lists return mean there is not a configuration
        if not r:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{hzArn}/route53-traffic-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": hzArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Route53.2] Route53 Hosted Zones should have traffic policies configured",
                "Description": f"Route53 Hosted Zone {hzId} named {hzName} does not have traffic policies configured. Traffic policies greatly simplifies the process of creating and maintaining records in large and complex traffic configurations, such as creating a configuration in which latency alias records reference weighted records, and the weighted records reference your resources in multiple AWS Regions. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Route53 traffic policy and how to configure it refer to the Using traffic flow to route DNS traffic section of the Amazon Route53 Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/traffic-flow.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Route53",
                    "AssetType": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hzArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": hzId,
                                "Name": hzName,
                                "PrivateZone": hzType
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
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
                "Id": f"{hzArn}/route53-traffic-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": hzArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53.2] Route53 Hosted Zones should have traffic policies configured",
                "Description": f"Route53 Hosted Zone {hzId} named {hzName} has traffic policies configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Route53 traffic policy and how to configure it refer to the Using traffic flow to route DNS traffic section of the Amazon Route53 Developer Guide.",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/traffic-flow.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Networking",
                    "AssetService": "Amazon Route53",
                    "AssetType": "Hosted Zone"
                },
                "Resources": [
                    {
                        "Type": "AwsRoute53HostedZone",
                        "Id": hzArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Id": hzId,
                                "Name": hzName,
                                "PrivateZone": hzType
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-5",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-10",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding