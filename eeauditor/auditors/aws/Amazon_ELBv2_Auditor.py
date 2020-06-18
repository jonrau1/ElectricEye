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

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
elbv2 = boto3.client("elbv2")
# loop through ELBv2 load balancers


def describe_load_balancers(cache):
    response = cache.get("describe_load_balancers")
    if response:
        return response
    cache["describe_load_balancers"] = elbv2.describe_load_balancers()
    return cache["describe_load_balancers"]


@registry.register_check("elbv2")
def elbv2_alb_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        if elbv2LbType == "application":
            try:
                response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
                elbv2Attributes = response["Attributes"]
                for attributes in elbv2Attributes:
                    if str(attributes["Key"]) == "access_logs.s3.enabled":
                        elbv2LoggingCheck = str(attributes["Value"])
                        iso8601Time = (
                            datetime.datetime.utcnow()
                            .replace(tzinfo=datetime.timezone.utc)
                            .isoformat()
                        )
                        if elbv2LoggingCheck == "false":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": elbv2Arn + "/elbv2-logging-check",
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
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
                                        "Partition": "aws",
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
                                "ProductArn": "arn:aws:securityhub:"
                                + awsRegion
                                + ":"
                                + awsAccountId
                                + ":product/"
                                + awsAccountId
                                + "/default",
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
                                        "Partition": "aws",
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
                        pass
            except Exception as e:
                print(e)
        else:
            pass


@registry.register_check("elbv2")
def elbv2_deletion_protection_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        try:
            response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
            elbv2Attributes = response["Attributes"]
            for attributes in elbv2Attributes:
                if str(attributes["Key"]) == "deletion_protection.enabled":
                    elbv2LoggingCheck = str(attributes["Value"])
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if elbv2LoggingCheck == "false":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/elbv2-deletion-protection-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                                    "Partition": "aws",
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                                    "Partition": "aws",
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
                    pass
        except Exception as e:
            print(e)


@registry.register_check("elbv2")
def elbv2_internet_facing_secure_listeners_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        try:
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            myElbv2Listeners = response["Listeners"]
            for listeners in myElbv2Listeners:
                listenerProtocol = str(listeners["Protocol"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if elbv2Scheme == "internet-facing" and listenerProtocol != "HTTPS" or "TLS":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/internet-facing-secure-listeners-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                                "Partition": "aws",
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
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                                "Partition": "aws",
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
        except Exception as e:
            print(e)


@registry.register_check("elbv2")
def elbv2_tls12_listener_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        try:
            response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
            myElbv2Listeners = response["Listeners"]
            for listeners in myElbv2Listeners:
                listenerProtocol = str(listeners["Protocol"])
                if listenerProtocol == "HTTPS" or "TLS":
                    listenerTlsPolicyCheck = str(listeners["SslPolicy"])
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if (
                        listenerTlsPolicyCheck != "ELBSecurityPolicy-TLS-1-2-2017-01"
                        or "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"
                        or "ELBSecurityPolicy-FS-1-2-2019-08"
                        or "ELBSecurityPolicy-FS-1-2-Res-2019-08"
                    ):
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": elbv2Arn + "/secure-listener-tls12-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 policies",
                            "Description": "ELB "
                            + elbv2LbType
                            + " load balancer "
                            + elbv2Name
                            + " does not enforce a TLS 1.2 policy. Refer to the remediation instructions to remediate this behavior",
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
                                    "Partition": "aws",
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
                            "Id": elbv2Arn + "/secure-listener-tls12-check",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "Title": "[ELBv2.4] Application and Network Load Balancers with HTTPS or TLS listeners should enforce TLS 1.2 policies",
                            "Description": "ELB "
                            + elbv2LbType
                            + " load balancer "
                            + elbv2Name
                            + " enforces a TLS 1.2 policy.",
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
                                    "Partition": "aws",
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
                else:
                    pass
        except Exception as e:
            print(e)


@registry.register_check("elbv2")
def elbv2_drop_invalid_header_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        response = elbv2.describe_load_balancer_attributes(LoadBalancerArn=elbv2Arn)
        elbv2Attributes = response["Attributes"]
        for attributes in elbv2Attributes:
            if str(attributes["Key"]) == "routing.http.drop_invalid_header_fields.enabled":
                elbv2DropInvalidHeaderCheck = str(attributes["Value"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if elbv2DropInvalidHeaderCheck == "false":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                                "Partition": "aws",
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
                        "Id": elbv2Arn + "/elbv2-drop-invalid-header-fields-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                                "Partition": "aws",
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
                                "ISO 27001:2013 A.14.1.3",
                            ],
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED",
                    }
                    yield finding
            else:
                pass


@registry.register_check("elbv2")
def elbv2_nlb_tls_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    response = describe_load_balancers(cache)
    myElbv2LoadBalancers = response["LoadBalancers"]
    for loadbalancers in myElbv2LoadBalancers:
        elbv2Arn = str(loadbalancers["LoadBalancerArn"])
        elbv2Name = str(loadbalancers["LoadBalancerName"])
        elbv2DnsName = str(loadbalancers["DNSName"])
        elbv2LbType = str(loadbalancers["Type"])
        elbv2Scheme = str(loadbalancers["Scheme"])
        elbv2VpcId = str(loadbalancers["VpcId"])
        elbv2IpAddressType = str(loadbalancers["IpAddressType"])
        if elbv2LbType == "network":
            try:
                response = elbv2.describe_listeners(LoadBalancerArn=elbv2Arn)
                for listeners in response["Listeners"]:
                    protocolCheck = str(listeners["Protocol"])
                    if protocolCheck == "TLS":
                        try:
                            response = elbv2.describe_load_balancer_attributes(
                                LoadBalancerArn=elbv2Arn
                            )
                            elbv2Attributes = response["Attributes"]
                            for attributes in elbv2Attributes:
                                if str(attributes["Key"]) == "access_logs.s3.enabled":
                                    elbv2LoggingCheck = str(attributes["Value"])
                                    iso8601Time = (
                                        datetime.datetime.utcnow()
                                        .replace(tzinfo=datetime.timezone.utc)
                                        .isoformat()
                                    )
                                    if elbv2LoggingCheck == "false":
                                        finding = {
                                            "SchemaVersion": "2018-10-08",
                                            "Id": elbv2Arn + "/tls-nlb-logging-check",
                                            "ProductArn": "arn:aws:securityhub:"
                                            + awsRegion
                                            + ":"
                                            + awsAccountId
                                            + ":product/"
                                            + awsAccountId
                                            + "/default",
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
                                                    "Partition": "aws",
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
                                            "ProductArn": "arn:aws:securityhub:"
                                            + awsRegion
                                            + ":"
                                            + awsAccountId
                                            + ":product/"
                                            + awsAccountId
                                            + "/default",
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
                                                    "Partition": "aws",
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
                                    pass
                        except Exception as e:
                            print(e)
                    else:
                        pass
            except Exception as e:
                print(e)
        else:
            pass
