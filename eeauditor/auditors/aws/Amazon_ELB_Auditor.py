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

# create boto3 clients
elb = boto3.client("elb")


@registry.register_check("elb")
def internet_facing_clb_https_listener_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response["LoadBalancerDescriptions"]:
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = (
            "arn:aws:elasticloadbalancing:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":loadbalancer/"
            + clbName
        )
        clbScheme = str(classicbalancer["Scheme"])
        if clbScheme == "internet-facing":
            for listeners in classicbalancer["ListenerDescriptions"]:
                listenerProtocol = str(listeners["Listener"]["Protocol"])
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if listenerProtocol != "HTTPS" or "SSL":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": clbArn + "/classic-loadbalancer-secure-listener-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": clbArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ELB.1] Classic load balancers that are internet-facing should use secure listeners",
                        "Description": "Classic load balancer "
                        + clbName
                        + " does not use a secure listener (HTTPS or SSL). Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on classic load balancer HTTPS listeners refer to the Create a Classic Load Balancer with an HTTPS Listener section of the Classic Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-create-https-ssl-load-balancer.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbLoadBalancer",
                                "Id": clbArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {"Other": {"LoadBalancerName": clbName}},
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
                        "Id": clbArn + "/classic-loadbalancer-secure-listener-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": clbArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ELB.1] Classic load balancers that are internet-facing should use secure listeners",
                        "Description": "Classic load balancer "
                        + clbName
                        + " uses a secure listener (HTTPS or SSL).",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on classic load balancer HTTPS listeners refer to the Create a Classic Load Balancer with an HTTPS Listener section of the Classic Load Balancers User Guide.",
                                "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-create-https-ssl-load-balancer.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsElbLoadBalancer",
                                "Id": clbArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {"Other": {"LoadBalancerName": clbName}},
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
            print("Ignoring internal CLB")
            pass


@registry.register_check("elb")
def clb_https_listener_tls12_policy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response["LoadBalancerDescriptions"]:
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = (
            "arn:aws:elasticloadbalancing:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":loadbalancer/"
            + clbName
        )
        for listeners in classicbalancer["ListenerDescriptions"]:
            listenerPolicies = str(listeners["PolicyNames"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if listenerPolicies == "[]":
                pass
            elif listenerPolicies == "ELBSecurityPolicy-TLS-1-2-2017-01":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clbArn + "/classic-loadbalancer-tls12-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ELB.2] Classic load balancers should use TLS 1.2 listener policies",
                    "Description": "Classic load balancer "
                    + clbName
                    + " does not use a TLS 1.2 listener policy.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on classic load balancer listener policies refer to the Predefined SSL Security Policies for Classic Load Balancers section of the Classic Load Balancers User Guide.",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElbLoadBalancer",
                            "Id": clbArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"LoadBalancerName": clbName}},
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
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clbArn + "/classic-loadbalancer-tls12-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[ELB.2] Classic load balancers should use TLS 1.2 listener policies",
                    "Description": "Classic load balancer "
                    + clbName
                    + " does not use a TLS 1.2 listener policy. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on classic load balancer listener policies refer to the Predefined SSL Security Policies for Classic Load Balancers section of the Classic Load Balancers User Guide.",
                            "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsElbLoadBalancer",
                            "Id": clbArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"LoadBalancerName": clbName}},
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


@registry.register_check("elb")
def clb_cross_zone_balancing_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response["LoadBalancerDescriptions"]:
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = (
            "arn:aws:elasticloadbalancing:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":loadbalancer/"
            + clbName
        )
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        crossZoneCheck = str(
            response["LoadBalancerAttributes"]["CrossZoneLoadBalancing"]["Enabled"]
        )
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if crossZoneCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clbArn + "/classic-loadbalancer-cross-zone-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ELB.3] Classic load balancers should have cross-zone load balancing configured",
                "Description": "Classic load balancer "
                + clbName
                + " does not have cross-zone load balancing configured. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on cross-zone load balancing refer to the Configure Cross-Zone Load Balancing for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
                "Id": clbArn + "/classic-loadbalancer-cross-zone-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ELB.3] Classic load balancers should have cross-zone load balancing configured",
                "Description": "Classic load balancer "
                + clbName
                + " has cross-zone load balancing configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on cross-zone load balancing refer to the Configure Cross-Zone Load Balancing for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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


@registry.register_check("elb")
def clb_connection_draining_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response["LoadBalancerDescriptions"]:
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = (
            "arn:aws:elasticloadbalancing:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":loadbalancer/"
            + clbName
        )
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        connectionDrainCheck = str(
            response["LoadBalancerAttributes"]["ConnectionDraining"]["Enabled"]
        )
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if connectionDrainCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clbArn + "/classic-loadbalancer-connection-draining-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ELB.4] Classic load balancers should have connection draining configured",
                "Description": "Classic load balancer "
                + clbName
                + " does not have connection draining configured. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on connection draining refer to the Configure Connection Draining for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
                "Id": clbArn + "/classic-loadbalancer-connection-draining-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ELB.4] Classic load balancers should have connection draining configured",
                "Description": "Classic load balancer "
                + clbName
                + " does not have connection draining configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on connection draining refer to the Configure Connection Draining for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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


@registry.register_check("elb")
def clb_access_logging_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    # loop through classic load balancers
    response = elb.describe_load_balancers()
    for classicbalancer in response["LoadBalancerDescriptions"]:
        clbName = str(classicbalancer["LoadBalancerName"])
        clbArn = (
            "arn:aws:elasticloadbalancing:"
            + awsRegion
            + ":"
            + awsAccountId
            + ":loadbalancer/"
            + clbName
        )
        response = elb.describe_load_balancer_attributes(LoadBalancerName=clbName)
        accessLogCheck = str(response["LoadBalancerAttributes"]["AccessLog"]["Enabled"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if accessLogCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": clbArn + "/classic-loadbalancer-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ELB.5] Classic load balancers should enable access logging",
                "Description": "Classic load balancer "
                + clbName
                + " does not have access logging enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on access logging refer to the Access Logs for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
                "Id": clbArn + "/classic-loadbalancer-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": clbArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ELB.5] Classic load balancers should enable access logging",
                "Description": "Classic load balancer "
                + clbName
                + " does not have access logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on access logging refer to the Access Logs for Your Classic Load Balancer section of the Classic Load Balancers User Guide.",
                        "Url": "https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsElbLoadBalancer",
                        "Id": clbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"LoadBalancerName": clbName}},
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
