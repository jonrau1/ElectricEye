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

def describe_vpcs(cache, session):
    ec2 = session.client("ec2")
    response = cache.get("describe_vpcs")
    if response:
        return response
    cache["describe_vpcs"] = ec2.describe_vpcs(DryRun=False)
    return cache["describe_vpcs"]

@registry.register_check("route53resolver")
def vpc_route53_query_logging_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.1] VPCs should have Route 53 Resolver DNS Query Logging configured"""
    route53resolver = session.client("route53resolver")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache, session)["Vpcs"]:
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
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("route53resolver")
def vpc_route53_resolver_firewall_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.2] VPCs should have Route 53 Resolver DNS Firewalls associated"""
    route53resolver = session.client("route53resolver")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache, session)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # Check for Firewall Associations filtered by VPC ID. 
        # If any empty list is returned there is not any
        r = route53resolver.list_firewall_rule_group_associations(VpcId=vpcId)

        # this is a failing check due to empty list comprehension
        if not r["FirewallRuleGroupAssociations"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsfw-associated-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Route53Resolver.2] VPCs should have Route 53 Resolver DNS Firewalls associated",
                "Description": f"VPC {vpcId} does not have a Route 53 Resolve DNS Firewall associated with it. With Route 53 Resolver DNS Firewall, you can filter and regulate outbound DNS traffic for your virtual private cloud (VPC). To do this, you create reusable collections of filtering rules in DNS Firewall rule groups, associate the rule groups to your VPC, and then monitor activity in DNS Firewall logs and metrics. Based on the activity, you can adjust the behavior of DNS Firewall accordingly. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up DNS Firewall refer to the Getting started with Route 53 Resolver DNS Firewall section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-getting-started.html",
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
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnsfw-associated-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53Resolver.2] VPCs should have Route 53 Resolver DNS Firewalls associated",
                "Description": f"VPC {vpcId} does not have a Route 53 Resolve DNS Firewall associated with it. With Route 53 Resolver DNS Firewall, you can filter and regulate outbound DNS traffic for your virtual private cloud (VPC). To do this, you create reusable collections of filtering rules in DNS Firewall rule groups, associate the rule groups to your VPC, and then monitor activity in DNS Firewall logs and metrics. Based on the activity, you can adjust the behavior of DNS Firewall accordingly. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up DNS Firewall refer to the Getting started with Route 53 Resolver DNS Firewall section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-getting-started.html",
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
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("route53resolver")
def vpc_route53_resolver_dnssec_validation_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.3] Consider enabling DNSSEC validation in your VPC for Route 53 Public Zones"""
    route53resolver = session.client("route53resolver")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Create a list of VPCs that have DNSSEC Validation enabled, as we cannot filter
    dnssecVpcs = []
    for r in route53resolver.list_resolver_dnssec_configs()["ResolverDnssecConfigs"]:
        if r["ValidationStatus"] == "ENABLED":
            dnssecVpcs.append(r["ResourceId"])
        else:
            continue
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache, session)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # This is a failing check as the VPC is not in the list of "dnssecVpcs"
        if vpcId not in dnssecVpcs:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnssec-validation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Route53Resolver.3] Consider enabling DNSSEC validation in your VPC for Route 53 Public Zones",
                "Description": f"VPC {vpcId} does not have DNS Security (DNSSEC) validation enabled. When you enable DNSSEC validation for a virtual private cloud (VPC) in Amazon Route 53, DNSSEC signatures are cryptographically checked to ensure that the response was not tampered with. Refer to the remediation instructions if you want to consider enabling this.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up DNSSEC validation refer to the Enabling DNSSEC validation in Amazon Route 53 section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dnssec-validation.html",
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": vpcArn + "/route53resolver-dnssec-validation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": vpcArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Route53Resolver.3] Consider enabling DNSSEC validation in your VPC for Route 53 Public Zones",
                "Description": f"VPC {vpcId} has DNS Security (DNSSEC) validation enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up DNSSEC validation refer to the Enabling DNSSEC validation in Amazon Route 53 section of the Amazon Route 53 Developer Guide",
                        "Url": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dnssec-validation.html",
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
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "PASSED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("route53resolver")
def vpc_route53_resolver_firewall_fail_open_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Route53Resolver.4] VPCs with Route 53 Resolver DNS Firewalls associated should be configured to Fail Open"""
    route53resolver = session.client("route53resolver")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Loop the VPCs in Cache
    for vpcs in describe_vpcs(cache, session)["Vpcs"]:
        vpcId = str(vpcs["VpcId"])
        vpcArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}vpc/{vpcId}"
        # Check for Firewall Associations filtered by VPC ID. 
        # If any empty list is returned there is not any
        r = route53resolver.list_firewall_rule_group_associations(VpcId=vpcId)

        # We will not generate failing findings on FAIL OPEN for VPCs without 
        # a DNSFW as it is redundant to the "no firewall" finding
        if not r["FirewallRuleGroupAssociations"]:
            continue
        else:
            config = route53resolver.get_firewall_config(ResourceId=vpcId)["FirewallConfig"]
            # This is a failing check, no Fail Open
            if config["FirewallFailOpen"] == "DISABLED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": vpcArn + "/route53resolver-dnsfw-failopen-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": vpcArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Route53Resolver.4] VPCs with Route 53 Resolver DNS Firewalls associated should be configured to Fail Open",
                    "Description": f"VPC {vpcId} has a Route 53 Resolve DNS Firewall associated with it that is not configured to Fail Open. If you enable fail open, Resolver allows queries through if it doesn't receive a reply from DNS Firewall. This approach favors availability over security which may be valuable. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on DNS Firewall Fail Open configuration refer to the DNS Firewall VPC configuration section of the Amazon Route 53 Developer Guide",
                            "Url": "hhttps://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-vpc-configuration.html",
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
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": vpcArn + "/route53resolver-dnsfw-failopen-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": vpcArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Route53Resolver.4] VPCs with Route 53 Resolver DNS Firewalls associated should be configured to Fail Open",
                    "Description": f"VPC {vpcId} has a Route 53 Resolve DNS Firewall associated with it that is configured to Fail Open.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on DNS Firewall Fail Open configuration refer to the DNS Firewall VPC configuration section of the Amazon Route 53 Developer Guide",
                            "Url": "hhttps://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-vpc-configuration.html",
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