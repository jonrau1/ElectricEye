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
import os
import datetime
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
shield = boto3.client("shield")
route53 = boto3.client("route53")
elbclassic = boto3.client("elb")
elbv2 = boto3.client("elbv2")
ec2 = boto3.client("ec2")
cloudfront = boto3.client("cloudfront")

#put conditional in each individual function

@registry.register_check("shield")
def shield_advanced_route_53_protection_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = route53.list_hosted_zones()
        for hostedzone in response["HostedZones"]:
            rawHzId = str(hostedzone["Id"])
            hostedZoneId = rawHzId.replace("/hostedzone/", "")
            hostedZoneArn = "arn:aws:route53:::hostedzone/" + hostedZoneId
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                # this is a passing check
                response = shield.describe_protection(ResourceArn=hostedZoneArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": hostedZoneArn + "/route53-shield-adv-protection-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": hostedZoneArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ShieldAdvanced.1] Route 53 Hosted Zones should be protected by Shield Advanced",
                    "Description": "Route53 Hosted Zone "
                    + hostedZoneId
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsRoute53HostedZone",
                            "Id": hostedZoneArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"hostedZoneId": hostedZoneId}},
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
            except Exception as e:
                if (
                    str(e)
                    == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist."
                ):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": hostedZoneArn
                        + "/route53-shield-adv-protection-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": hostedZoneArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.1] Route 53 Hosted Zones should be protected by Shield Advanced",
                        "Description": "Route53 Hosted Zone "
                        + hostedZoneId
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsRoute53HostedZone",
                                "Id": hostedZoneArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {"hostedZoneId": hostedZoneId}
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
                    print(e)

@registry.register_check("shield")
def shield_advanced_elb_protection_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = elbclassic.describe_load_balancers()
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
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                # this is a passing check
                response = shield.describe_protection(ResourceArn=clbArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": clbArn + "/classiclb-shield-adv-protection-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": clbArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ShieldAdvanced.2] Classic Load Balancers should be protected by Shield Advanced",
                    "Description": "Classic Load Balancer "
                    + clbName
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
            except Exception as e:
                if (
                    str(e)
                    == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist."
                ):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": clbArn + "/classiclb-shield-adv-protection-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": clbArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.2] Classic Load Balancers should be protected by Shield Advanced",
                        "Description": "Classic Load Balancer "
                        + clbName
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                    print(e)

@registry.register_check("shield")
def shield_advanced_elb_v2_protection_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = elbv2.describe_load_balancers()
        for loadbalancer in response["LoadBalancers"]:
            elbv2Name = str(loadbalancer["LoadBalancerName"])
            elbv2Arn = str(loadbalancer["LoadBalancerArn"])
            elbv2DnsName = str(loadbalancer["DNSName"])
            elbv2LbType = str(loadbalancer["Type"])
            elbv2Scheme = str(loadbalancer["Scheme"])
            elbv2VpcId = str(loadbalancer["VpcId"])
            elbv2IpAddressType = str(loadbalancer["IpAddressType"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                # this is a passing check
                response = shield.describe_protection(ResourceArn=elbv2Arn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": elbv2Arn + "/elbv2-shield-adv-protection-check",
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
                    "Title": "[ShieldAdvanced.3] ELBv2 Load Balancers should be protected by Shield Advanced",
                    "Description": "ELBv2 "
                    + elbv2LbType
                    + " load balancer "
                    + elbv2Name
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
            except Exception as e:
                if (
                    str(e)
                    == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist."
                ):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": elbv2Arn + "/elbv2-shield-adv-protection-check",
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
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.3] ELBv2 Load Balancers should be protected by Shield Advanced",
                        "Description": "ELBv2 "
                        + elbv2LbType
                        + " load balancer "
                        + elbv2Name
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
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
                    print(e)

@registry.register_check("shield")
def shield_advanced_eip_protection_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
            print("Shield Advanced APIs are only available in North Virginia")
    else:       
        response = ec2.describe_addresses()
        for elasticip in response["Addresses"]:
            # arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:eip/${EIP1.AllocationId}
            allocationId = str(elasticip["AllocationId"])
            eipAllocationArn = (
                "arn:aws:ec2:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":eip-allocation/"
                + allocationId
            )
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                # this is a passing check
                response = shield.describe_protection(ResourceArn=eipAllocationArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": eipAllocationArn
                    + "/elasticip-shield-adv-protection-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": eipAllocationArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ShieldAdvanced.4] Elastic IPs should be protected by Shield Advanced",
                    "Description": "Elastic IP allocation "
                    + allocationId
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Eip",
                            "Id": eipAllocationArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {"Other": {"AllocationId": allocationId}},
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
            except Exception as e:
                if (
                    str(e)
                    == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist."
                ):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": eipAllocationArn
                        + "/elasticip-shield-adv-protection-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": eipAllocationArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.4] Elastic IPs should be protected by Shield Advanced",
                        "Description": "Elastic IP allocation "
                        + allocationId
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEc2Eip",
                                "Id": eipAllocationArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {"AllocationId": allocationId}
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
                    print(e)

@registry.register_check("shield")
def shield_advanced_cloudfront_protection_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = cloudfront.list_distributions()
        cfDistros = response["DistributionList"]["Items"]
        for distro in cfDistros:
            distroId = str(distro["Id"])
            distroArn = str(distro["ARN"])
            distroDomainName = str(distro["DomainName"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            try:
                # this is a passing check
                response = shield.describe_protection(ResourceArn=distroArn)
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": distroArn + "/cloudfront-shield-adv-protection-check",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": distroArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[ShieldAdvanced.5] CloudFront distributions should be protected by Shield Advanced",
                    "Description": "CloudFront distribution "
                    + distroId
                    + " is protected by Shield Advanced.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                            "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCloudFrontDistribution",
                            "Id": distroArn,
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCloudFrontDistribution": {
                                    "DomainName": distroDomainName
                                }
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
            except Exception as e:
                if (
                    str(e)
                    == "An error occurred (ResourceNotFoundException) when calling the DescribeProtection operation: The referenced protection does not exist."
                ):
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": distroArn + "/cloudfront-shield-adv-protection-check",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
                        "GeneratorId": distroArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ShieldAdvanced.5] CloudFront distributions should be protected by Shield Advanced",
                        "Description": "CloudFront distribution "
                        + distroId
                        + " is not protected by Shield Advanced. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on adding Shield Advanced protection to resources refer to the Adding AWS Shield Advanced Protection to AWS Resources section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                                "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloudFrontDistribution",
                                "Id": distroArn,
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCloudFrontDistribution": {
                                        "DomainName": distroDomainName
                                    }
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
                    print(e)

@registry.register_check("shield")
def shield_advanced_drt_access_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = shield.describe_drt_access()
        iso8601Time = (
            datetime.datetime.utcnow()
            .replace(tzinfo=datetime.timezone.utc)
            .isoformat()
        )
        try:
            # this is a passing check
            drtRole = str(response["RoleArn"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/shield-adv-drt-iam-access-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.6] The DDoS Response Team (DRT) should be authorized to take action in your account",
                "Description": "The Shield Advanced DRT is authorized to take action in Account "
                + awsAccountId
                + " with the IAM role "
                + drtRole,
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on authorizing the DRT refer to the Authorize the DDoS Response Team section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/authorize-DRT.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/shield-adv-drt-iam-access-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.6] The DDoS Response Team (DRT) should be authorized to take action in your account",
                "Description": "The Shield Advanced DRT is not authorized to take action in Account "
                + awsAccountId
                + " . Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on authorizing the DRT refer to the Authorize the DDoS Response Team section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/authorize-DRT.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_drt_s3_bucket_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = shield.describe_drt_access()
        iso8601Time = (
            datetime.datetime.utcnow()
            .replace(tzinfo=datetime.timezone.utc)
            .isoformat()
        )
        try:
            logBucketList = str(response["LogBucketList"])
            print(logBucketList)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/shield-adv-drt-s3bucket-access-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.7] The DDoS Response Team (DRT) should be authorized to view your AWS Web Application Firewall (WAF) logging buckets",
                "Description": "The Shield Advanced DRT is authorized to view one or more WAF log S3 buckets in "
                + awsAccountId,
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on authorizing the DRT refer to the Authorize the DDoS Response Team section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/authorize-DRT.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/shield-adv-drt-s3bucket-access-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.7] The DDoS Response Team (DRT) should be authorized to view your AWS Web Application Firewall (WAF) logging buckets",
                "Description": "The Shield Advanced DRT is not authorized to view any WAF log S3 buckets in "
                + awsAccountId
                + " . Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on authorizing the DRT refer to the Authorize the DDoS Response Team section of the AWS WAF, AWS Firewall Manager, and AWS Shield Advanced Developer Guide",
                        "Url": "https://docs.aws.amazon.com/waf/latest/developerguide/authorize-DRT.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-6",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AC-3",
                        "NIST SP 800-53 AC-16",
                        "NIST SP 800-53 AC-19",
                        "NIST SP 800-53 AC-24",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 PE-2",
                        "NIST SP 800-53 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("shield")
def shield_advanced_subscription_autorenew_check(cache: dict, awsAccountId: str, awsRegion: str) -> dict:
    if awsRegion != "us-east-1":
        print("Shield Advanced APIs are only available in North Virginia")
    else:
        response = shield.describe_subscription()
        renewCheck = str(response["Subscription"]["AutoRenew"])
        iso8601Time = (
            datetime.datetime.utcnow()
            .replace(tzinfo=datetime.timezone.utc)
            .isoformat()
        )
        if renewCheck != "ENABLED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/shield-adv-subscription-auto-renew-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.8] Shield Advanced subscription should be set to auto-renew",
                "Description": "The Shield Advanced subscription for "
                + awsAccountId
                + " is not set to auto-renew. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To update the subscription renewel use the UpdateSubscription API, refer to the link for more details.",
                        "Url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_UpdateSubscription.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
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
                "Id": awsAccountId + "/shield-adv-subscription-auto-renew-check",
                "ProductArn": "arn:aws:securityhub:"
                + awsRegion
                + ":"
                + awsAccountId
                + ":product/"
                + awsAccountId
                + "/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ShieldAdvanced.8] Shield Advanced subscription should be set to auto-renew",
                "Description": "The Shield Advanced subscription for "
                + awsAccountId
                + " is set to auto-renew",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To update the subscription renewel use the UpdateSubscription API, refer to the link for more details.",
                        "Url": "https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_UpdateSubscription.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": "AWS::::Account:" + awsAccountId,
                        "Partition": "aws",
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
