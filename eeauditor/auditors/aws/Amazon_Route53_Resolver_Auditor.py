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

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# create boto3 clients
ec2 = boto3.client("ec2")
route53resolver = boto3.client("route53resolver")

# loop through vpcs
def describe_vpcs(cache):
    response = cache.get("describe_vpcs")
    if response:
        return response
    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)
    return cache["describe_vpcs"]

@registry.register_check("route53resolver")
def vpc_route53_query_logging_association_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache=cache)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # Check for Query Log Configs filtered by VPC ID. 
        # If any empty list is returned there is not query logging configured
        r = route53resolver.list_resolver_query_log_config_associations(
            Filters=[
                {
                    'Name': 'ResourceId',
                    'Values': [vpcId]
                }
            ]
        )
        # this is a failing check due to empty list comprehension
        if not r["ResolverQueryLogConfigAssociations"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsql-attached-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured",
                "Description": f"VPC {vpcId} does not have Route 53 DNS Query Logging configured. DNS Query Logging provides rich details about outbound DNS resolutions originating from your VPC which can be crucial for application troubleshooting and security use cases. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Query Logging refer to the Managing Resolver query logging configurations section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Vpc": {
                                "State": "available"
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsql-attached-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured",
                "Description": f"VPC {vpcId} does not have Route 53 DNS Query Logging configured. DNS Query Logging provides rich details about outbound DNS resolutions originating from your VPC which can be crucial for application troubleshooting and security use cases. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Query Logging refer to the Managing Resolver query logging configurations section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Vpc": {
                                "State": "available"
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("route53resolver")
def vpc_route53_resolver_firewall_association_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.2] VPCs should have Route 53 Resolver DNS Firewalls associated"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache=cache)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # Check for Query Log Configs filtered by VPC ID. 
        # If any empty list is returned there is not query logging configured
        r = route53resolver.list_firewall_rule_group_associations(VpcId=vpcId)

        print(r)

        '''
        # this is a failing check due to empty list comprehension
        if not r["ResolverQueryLogConfigAssociations"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsql-attached-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured",
                "Description": f"VPC {vpcId} does not have Route 53 DNS Query Logging configured. DNS Query Logging provides rich details about outbound DNS resolutions originating from your VPC which can be crucial for application troubleshooting and security use cases. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Query Logging refer to the Managing Resolver query logging configurations section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Vpc": {
                                "State": "available"
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsql-attached-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured",
                "Description": f"VPC {vpcId} does not have Route 53 DNS Query Logging configured. DNS Query Logging provides rich details about outbound DNS resolutions originating from your VPC which can be crucial for application troubleshooting and security use cases. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up Query Logging refer to the Managing Resolver query logging configurations section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logging-configurations-managing.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsEc2Vpc",
                        "Id": vpcArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Vpc": {
                                "State": "available"
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        '''

@registry.register_check("route53resolver")
def vpc_route53_resolver_firewall_orphaned_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.4] Route 53 Resolver DNS Firewall Rule Groups should be in an associated state"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Find all Firewall Rule Groups
    fw = route53resolver.list_firewall_rule_groups()
    if not fw["FirewallRuleGroups"]:
        pass
    else:
        for groups in fw["FirewallRuleGroups"]:
            fwGroupId = groups["Id"]
            # Describe the Rule Group to find attachment state
            response = route53resolver.get_firewall_rule_group(
                FirewallRuleGroupId=fwGroupId
            )
            print(response)
####