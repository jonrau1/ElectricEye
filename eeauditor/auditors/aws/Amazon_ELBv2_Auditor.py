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

# boto3 clients
elbv2 = boto3.client("elbv2")
ec2 = boto3.client("ec2")

def describe_load_balancers(cache):
    # loop through ELBv2 load balancers
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elbv2.describe_load_balancers()
    return cache["describe_load_balancers"]

@registry.register_check("elbv2")
def elbv2_alb_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.1] Application Load Balancers should have access logging enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        if elbv2LbType == "application":
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response["Attributes"]
            for attributes in elbv2Attributes:
                if str(attributes["Key"]) == "access_logs.s3.enabled":
                    elbv2LoggingCheck = str(attributes["Value"])
                    if elbv2LoggingCheck == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ELBv2.1] Application Load Balancers should have access logging enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + " does not have access logging enabled. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                        }
                                    },
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
                                    "ISO 27001:2013 A.16.1.7",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.1] Application and Network Load Balancers should have access logging enabled",
                            "Description": "ELB "
                            + elbv2LbType
                            + " load balancer "
                            + elbv2Name
                            + " has access logging enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Access Logs for Your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                        },
                                    },
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
                                    "ISO 27001:2013 A.16.1.7",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                else:
                    continue
        else:
            continue

@registry.register_check("elbv2")
def elbv2_deletion_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response["Attributes"]
        for attributes in elbv2Attributes:
            if str(attributes["Key"]) == "deletion_protection.enabled":
                elbv2LoggingCheck = str(attributes["Value"])
                if elbv2LoggingCheck == "false":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-deletion-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " does not have deletion protection enabled. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                },
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
                        "Id": elbv2Arn + "/elbv2-deletion-protection-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.2] Application and Network Load Balancers should have deletion protection enabled",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " has deletion protection enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Deletion Protection section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                },
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
            else:
                continue

@registry.register_check("elbv2")
def elbv2_internet_facing_secure_listeners_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
        myElbv2Listeners = response["Listeners"]
        for listeners in myElbv2Listeners:
            listenerProtocol = str(listeners["Protocol"])
            if (elbv2Scheme == "internet-facing" 
                and listenerProtocol != "HTTPS" or "TLS"
            ):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": elbv2Arn + "/internet-facing-secure-listeners-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured",
                    "Description": "ELB "
                    + elbv2LbType
                    + " load balancer "
                    + elbv2Name
                    + " does not have a secure listener configured. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElbv2LoadBalancer",
                            "Id": elbv2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElbv2LoadBalancer": {
                                    "DNSName": elbv2DnsName,
                                    "IpAddressType": elbv2IpAddressType,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2LbType,
                                    "VpcId": elbv2VpcId,
                                },
                            },
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
                    "Id": elbv2Arn + "/internet-facing-secure-listeners-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": elbv2Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ELBv2.3] Internet-facing Application and Network Load Balancers should have secure listeners configured",
                    "Description": "ELB "
                    + elbv2LbType
                    + " load balancer "
                    + elbv2Name
                    + " has a secure listener configured.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Create an HTTPS Listener for Your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElbv2LoadBalancer",
                            "Id": elbv2Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsElbv2LoadBalancer": {
                                    "DNSName": elbv2DnsName,
                                    "IpAddressType": elbv2IpAddressType,
                                    "Scheme": elbv2Scheme,
                                    "Type": elbv2LbType,
                                    "VpcId": elbv2VpcId,
                                },
                            },
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

@registry.register_check("elbv2")
def elbv2_tls12_listener_policy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # valid TLS 1.2 and 1.3 Policies
    goodTls = [
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-FS-1-2-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10",
        "ELBSecurityPolicy-TLS13-1-3-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-2021-06" 
    ]

    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
        myElbv2Listeners = response["Listeners"]
        for listeners in myElbv2Listeners:
            listenerProtocol = str(listeners["Protocol"])
            if listenerProtocol == "HTTPS" or "TLS":
                try:
                    listenerTlsPolicyCheck = str(listeners["SslPolicy"])
                except KeyError:
                    # ignore ALB/NLB without HTTPS/TLS
                    continue
                # Evaluate listener
                if listenerTlsPolicyCheck not in goodTls:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/secure-listener-tls12-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "HIGH"},
                        "Confidence": 99,
                        "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies",
                        "Description": f"The {elbv2LbType} ELBv2 load balancer named {elbv2Name} does not enforce a TLS 1.2 or TLS 1.3 policy and uses the {listenerTlsPolicyCheck} policy. Using security policies that support backwards compatability with TLS 1.0 or TLS 1.1 can lead to downgrade attacks and potential exploitability of legacy ciphersuites, consider upgrading to Forward Secret TLS 1.2 or TLS 1.3 ciphersuites to prevent this. Refer to the remediation instructions to remediate this behavior if not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 security policies and updating them refer to the Update an HTTPS listener for your Application Load Balancer section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-certificates.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                    "Other": {
                                        "SslPolicy": listenerTlsPolicyCheck
                                    }
                                },
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
                        "Id": elbv2Arn + "/secure-listener-tls12-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 or TLS 1.3 policies",
                        "Description": f"The {elbv2LbType} ELBv2 load balancer named {elbv2Name} enforces a TLS 1.2 or TLS 1.3 policy and uses the {listenerTlsPolicyCheck} policy.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on ELBv2 Access Logging and how to configure it refer to the Security Policies section of the Application Load Balancers User Guide. For Network Load Balancer logging please refer to the NLB User Guide",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                    "Other": {
                                        "SslPolicy": listenerTlsPolicyCheck
                                    }
                                }
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
                                "ISO 27001:2013 A.14.1.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
            else:
                continue

@registry.register_check("elbv2")
def elbv2_drop_invalid_header_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response["Attributes"]
        for attributes in elbv2Attributes:
            if str(attributes["Key"]) == "routing.http.drop_invalid_header_fields.enabled":
                elbv2DropInvalidHeaderCheck = str(attributes["Value"])
                if elbv2DropInvalidHeaderCheck == "false":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " does not drop invalid HTTP header fields. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-5",
                                "NIST SP 800-53 AC-4",
                                "NIST SP 800-53 AC-10",
                                "NIST SP 800-53 SC-7",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.1.3",
                                "ISO 27001:2013 A.13.2.1",
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
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": elbv2Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELBv2.5] Application Load Balancers should drop invalid HTTP header fields",
                        "Description": "ELB "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " drops invalid HTTP header fields.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on dropping invalid HTTP headers refer to the routing.http.drop_invalid_header_fields.enabled section of the Application Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbv2LoadBalancer",
                                "Id": elbv2Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsElbv2LoadBalancer": {
                                        "DNSName": elbv2DnsName,
                                        "IpAddressType": elbv2IpAddressType,
                                        "Scheme": elbv2Scheme,
                                        "Type": elbv2LbType,
                                        "VpcId": elbv2VpcId,
                                    },
                                },
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-5",
                                "NIST SP 800-53 AC-4",
                                "NIST SP 800-53 AC-10",
                                "NIST SP 800-53 SC-7",
                                "AICPA TSC CC6.1",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.1.3",
                                "ISO 27001:2013 A.13.2.1",
                                "ISO 27001:2013 A.14.1.2",
                                "ISO 27001:2013 A.14.1.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            else:
                continue

@registry.register_check("elbv2")
def elbv2_nlb_tls_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        if elbv2LbType == "network":
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            for listeners in response["Listeners"]:
                protocolCheck = str(listeners["Protocol"])
                if protocolCheck == "TLS":
                    response = elbv2.describe_load_balancer_attributes(
                        LoadBalancerArn=elbv2Arn
                    )
                    elbv2Attributes = response["Attributes"]
                    for attributes in elbv2Attributes:
                        if str(attributes["Key"]) == "access_logs.s3.enabled":
                            elbv2LoggingCheck = str(attributes["Value"])
                            if elbv2LoggingCheck == "false":
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": elbv2Arn + "/tls-nlb-logging-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": elbv2Arn,
                                    "AwsAccountId": awsAccountId,
                                    "Types": [
                                        "Software and Configuration Checks/AWS Security Best Practices"
                                    ],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "LOW"},
                                    "Confidence": 99,
                                    "Title": "[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled",
                                    "Description": "Network load balancer "
                                    + elbv2Name
                                    + " does not have access logging enabled. Refer to the remediation instructions to remediate this behavior",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on Network Load Balancer Access Logging and how to configure it refer to the Access Logs for Your Network Load Balancer section of the Network Load Balancers User Guide.",
                                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html",
                                        }
                                    },
                                    "ProductFields": {"Product Name": "ElectricEye"},
                                    "Resources": [
                                        {
                                            "Type": "AwsElbv2LoadBalancer",
                                            "Id": elbv2Arn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion,
                                            "Details": {
                                                "AwsElbv2LoadBalancer": {
                                                    "DNSName": elbv2DnsName,
                                                    "IpAddressType": elbv2IpAddressType,
                                                    "Scheme": elbv2Scheme,
                                                    "Type": elbv2LbType,
                                                    "VpcId": elbv2VpcId,
                                                }
                                            },
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
                                            "ISO 27001:2013 A.16.1.7",
                                        ],
                                    },
                                    "Workflow": {"Status": "NEW"},
                                    "RecordState": "ACTIVE",
                                }
                                yield finding
                            else:
                                finding = {
                                    "SchemaVersion": "2018-10-08",
                                    "Id": elbv2Arn + "/tls-nlb-logging-check",
                                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                    "GeneratorId": elbv2Arn,
                                    "AwsAccountId": awsAccountId,
                                    "Types": [
                                        "Software and Configuration Checks/AWS Security Best Practices"
                                    ],
                                    "FirstObservedAt": iso8601Time,
                                    "CreatedAt": iso8601Time,
                                    "UpdatedAt": iso8601Time,
                                    "Severity": {"Label": "INFORMATIONAL"},
                                    "Confidence": 99,
                                    "Title": "[ELBv2.6] Network Load Balancers with TLS listeners should have access logging enabled",
                                    "Description": "Network load balancer "
                                    + elbv2Name
                                    + " has access logging enabled.",
                                    "Remediation": {
                                        "Recommendation": {
                                            "Text": "For more information on Network Load Balancer Access Logging and how to configure it refer to the Access Logs for Your Network Load Balancer section of the Network Load Balancers User Guide.",
                                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html",
                                        }
                                    },
                                    "ProductFields": {"Product Name": "ElectricEye"},
                                    "Resources": [
                                        {
                                            "Type": "AwsElbv2LoadBalancer",
                                            "Id": elbv2Arn,
                                            "Partition": awsPartition,
                                            "Region": awsRegion,
                                            "Details": {
                                                "AwsElbv2LoadBalancer": {
                                                    "DNSName": elbv2DnsName,
                                                    "IpAddressType": elbv2IpAddressType,
                                                    "Scheme": elbv2Scheme,
                                                    "Type": elbv2LbType,
                                                    "VpcId": elbv2VpcId,
                                                }
                                            },
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
                                            "ISO 27001:2013 A.16.1.7",
                                        ],
                                    },
                                    "Workflow": {"Status": "RESOLVED"},
                                    "RecordState": "ARCHIVED",
                                }
                                yield finding
                        else:
                            continue
                else:
                    continue
        else:
            continue

@registry.register_check("elbv2")
def elbv2_alb_http_desync_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for lb in describe_load_balancers(cache)["LoadBalancers"]:
        elbv2Arn = str(lb["LoadBalancerArn"])
        elbv2Name = str(lb["LoadBalancerName"])
        elbv2DnsName = str(lb["DNSName"])
        elbv2LbType = str(lb["Type"])
        elbv2Scheme = str(lb["Scheme"])
        elbv2VpcId = str(lb["VpcId"])
        elbv2IpAddressType = str(lb["IpAddressType"])
        if elbv2LbType == "application":
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response["Attributes"]
            for attributes in elbv2Attributes:
                if str(attributes["Key"]) == "routing.http.desync_mitigation_mode":
                    elbv2LoggingCheck = str(attributes["Value"])
                    if elbv2LoggingCheck == "monitor":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-alb-http-desync-protection-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + " does not have HTTP Desync protection enabled (it is set to Monitor). Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 HTTP Desync protection and how to configure it refer to the Desync mitigation mode section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.IP-1",
                                    "NIST SP 800-53 CM-2",
                                    "NIST SP 800-53 CM-3",
                                    "NIST SP 800-53 CM-4",
                                    "NIST SP 800-53 CM-5",
                                    "NIST SP 800-53 CM-6",
                                    "NIST SP 800-53 CM-7",
                                    "NIST SP 800-53 CM-9",
                                    "NIST SP 800-53 SA-10",
                                    "AICPA TSC A1.3",
                                    "AICPA TSC CC1.4",
                                    "AICPA TSC CC5.3",
                                    "AICPA TSC CC6.2",
                                    "AICPA TSC CC7.1",
                                    "AICPA TSC CC7.3",
                                    "AICPA TSC CC7.4",
                                    "ISO 27001:2013 A.12.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                    "ISO 27001:2013 A.12.6.2",
                                    "ISO 27001:2013 A.14.2.2",
                                    "ISO 27001:2013 A.14.2.3",
                                    "ISO 27001:2013 A.14.2.4"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-alb-http-desync-protection-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.7] Application Load Balancers should have HTTP Desync protection enabled",
                            "Description": "Application load balancer "
                            + elbv2Name
                            + "has HTTP Desync protection enabled (set to Defensive or Strictest).",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ELBv2 HTTP Desync protection and how to configure it refer to the Desync mitigation mode section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                        },
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.IP-1",
                                    "NIST SP 800-53 CM-2",
                                    "NIST SP 800-53 CM-3",
                                    "NIST SP 800-53 CM-4",
                                    "NIST SP 800-53 CM-5",
                                    "NIST SP 800-53 CM-6",
                                    "NIST SP 800-53 CM-7",
                                    "NIST SP 800-53 CM-9",
                                    "NIST SP 800-53 SA-10",
                                    "AICPA TSC A1.3",
                                    "AICPA TSC CC1.4",
                                    "AICPA TSC CC5.3",
                                    "AICPA TSC CC6.2",
                                    "AICPA TSC CC7.1",
                                    "AICPA TSC CC7.3",
                                    "AICPA TSC CC7.4",
                                    "ISO 27001:2013 A.12.1.2",
                                    "ISO 27001:2013 A.12.5.1",
                                    "ISO 27001:2013 A.12.6.2",
                                    "ISO 27001:2013 A.14.2.2",
                                    "ISO 27001:2013 A.14.2.3",
                                    "ISO 27001:2013 A.14.2.4"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                else:
                    continue
        else:
            continue

@registry.register_check("elbv2")
def elbv2_alb_sg_risk_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    # Evaluations
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2LbType = str(loadbalancers["Type"])
        # only applicable for ALBs...
        if elbv2LbType == "application":
            elbv2Arn = str(loadbalancers["LoadBalancerArn"])
            elbv2Name = str(loadbalancers["LoadBalancerName"])
            elbv2DnsName = str(loadbalancers["DNSName"])
            elbv2Scheme = str(loadbalancers["Scheme"])
            elbv2VpcId = str(loadbalancers["VpcId"])
            elbv2IpAddressType = str(loadbalancers["IpAddressType"])
            # Create empty list per ELB to store all Listener Ports and SG IDs
            lbSgs = []
            listenerPorts = []
            for sg in loadbalancers["SecurityGroups"]:
                lbSgs.append(str(sg))
            # feed ARN into Listener Call to find all Listeners
            for listener in elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)["Listeners"]:
                # we will stick regular ports AND the redirect action ports (if they exist) into the Port List
                portNumber = str(listener["Port"])
                if portNumber not in listenerPorts:
                    listenerPorts.append(portNumber)
                # now loop the redirects (if there)
                for actions in listener["DefaultActions"]:
                    try:
                        redirectPort = str(actions["RedirectConfig"]["Port"])
                        if redirectPort not in listenerPorts:
                            listenerPorts.append(redirectPort)
                    except KeyError:
                        continue
            # Now we can start to perform evaluations per SG
            for sgid in lbSgs:
                # pass SG ID to Describe SG Rules API via filter and loop each rule
                for sgrs in ec2.describe_security_group_rules(Filters=[{'Name': 'group-id','Values': [sgid]}])["SecurityGroupRules"]:
                    # if the from port or to port range is not within the Listener or Redirect Ports then it's a failing check
                    # we will skip egress rules though
                    if str(sgrs["IsEgress"]) == "True":
                        continue
                    if (str(sgrs["FromPort"]) or str(sgrs["ToPort"])) not in listenerPorts:
                        # this is a failing check - we will stop at the first fail
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-non-listener-sg-port-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access",
                            "Description": f"Application load balancer {elbv2Name} has a Security Group {sgid} that allows access to Ports not associated with any Listener or Redirect Rules. This may allow adversaries to circumvent your load balancer and directly discover or access downstream resources. If this configuration is not intended refer to the remediation guidance.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                            "SecurityGroups": lbSgs
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                        break
                    else:
                        # this is a passign check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-non-listener-sg-port-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": elbv2Arn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ELBv2.8] Application Load Balancer security groups should not allow non-Listener ports access",
                            "Description": f"Application load balancer {elbv2Name} does not allow access to Ports not associated with any Listener or Redirect Rules.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information on ALB security group reccomendations refer to the Security groups for your Application Load Balancer section of the Application Load Balancers User Guide.",
                                    "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html#security-group-recommended-rules"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsElbv2LoadBalancer",
                                    "Id": elbv2Arn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsElbv2LoadBalancer": {
                                            "DNSName": elbv2DnsName,
                                            "IpAddressType": elbv2IpAddressType,
                                            "Scheme": elbv2Scheme,
                                            "Type": elbv2LbType,
                                            "VpcId": elbv2VpcId,
                                            "SecurityGroups": lbSgs
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF PR.AC-3",
                                    "NIST SP 800-53 AC-1",
                                    "NIST SP 800-53 AC-17",
                                    "NIST SP 800-53 AC-19",
                                    "NIST SP 800-53 AC-20",
                                    "NIST SP 800-53 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
        else:
            continue