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

def describe_auto_scaling_groups(cache, session):
    autoscaling = session.client("autoscaling")
    response = cache.get("describe_auto_scaling_groups")
    if response:
        return response
    cache["describe_auto_scaling_groups"] = autoscaling.describe_auto_scaling_groups(MaxRecords=100)
    return cache["describe_auto_scaling_groups"]

@registry.register_check("autoscaling")
def autoscaling_scale_in_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Autoscaling.1] Autoscaling Groups should be configured to protect instances from scale-in"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for asg in describe_auto_scaling_groups(cache, session)["AutoScalingGroups"]:
        asgArn = asg["AutoScalingGroupARN"]
        asgName = asg["AutoScalingGroupName"]
        healthCheckType = asg["HealthCheckType"]
        # Check specific metadata
        scaleInProtection = str(asg["NewInstancesProtectedFromScaleIn"])
        if scaleInProtection == "False":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{asgArn}/asg-instance-scalein-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": asgArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Autoscaling.1] Autoscaling Groups should be configured to protect instances from scale-in",
                "Description": f"Autoscaling group {asgName} is not configured to protect instances from scale-in. To control whether an Auto Scaling group can terminate a particular instance when scaling in, use instance scale-in protection, Instance scale-in protection starts when the instance state is InService. Scale-in protection can help prevent application instability due to mulitiple scale events, but may also be detrimental due to over-provisioning. Review the remediation section for more information on this configuration.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about scale-in protection refer to the Using instance scale-in protection section of the Amazon EC2 Auto Scaling User Guide",
                        "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-instance-protection.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Compute",
                    "AssetService": "AWS Auto Scaling",
                    "AssetType": "Autoscaling Group"
                },
                "Resources": [
                    {
                        "Type": "AwsAutoScalingAutoScalingGroup",
                        "Id": asgArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsAutoScalingAutoScalingGroup": {
                                "HealthCheckType": healthCheckType
                            }
                        }
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
                        "ISO 27001:2013 A.17.2.1"
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
                "Id": f"{asgArn}/asg-instance-scalein-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": asgArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Autoscaling.1] Autoscaling Groups should be configured to protect instances from scale-in",
                "Description": f"Autoscaling group {asgName} is configured to protect instances from scale-in.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about scale-in protection refer to the Using instance scale-in protection section of the Amazon EC2 Auto Scaling User Guide",
                        "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-instance-protection.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Compute",
                    "AssetService": "AWS Auto Scaling",
                    "AssetType": "Autoscaling Group"
                },
                "Resources": [
                    {
                        "Type": "AwsAutoScalingAutoScalingGroup",
                        "Id": asgArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsAutoScalingAutoScalingGroup": {
                                "HealthCheckType": healthCheckType
                            }
                        }
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
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("autoscaling")
def autoscaling_load_balancer_healthcheck_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Autoscaling.2] Autoscaling Groups with load balancer targets should use ELB health checks"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for asg in describe_auto_scaling_groups(cache, session)["AutoScalingGroups"]:
        asgArn = asg["AutoScalingGroupARN"]
        asgName = asg["AutoScalingGroupName"]
        healthCheckType = asg["HealthCheckType"]
        # Check specific metadata
        asgLbs = asg["LoadBalancerNames"]
        asgTgs = asg["TargetGroupARNs"]
        # If either list is empty it means there are no ELBs or ELBv2s associated with this ASG
        if not (asgLbs or asgTgs):
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{asgArn}/asg-elb-asgs-elb-healthcheck-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": asgArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Autoscaling.2] Autoscaling Groups with load balancer targets should use ELB health checks",
                "Description": f"Autoscaling group {asgName} does not have any ELB or Target Groups associated and is not in scope for this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information about enabling ELB health checks refer to the Add Elastic Load Balancing health checks to an Auto Scaling group section of the Amazon EC2 Auto Scaling User Guide",
                        "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Compute",
                    "AssetService": "AWS Auto Scaling",
                    "AssetType": "Autoscaling Group"
                },
                "Resources": [
                    {
                        "Type": "AwsAutoScalingAutoScalingGroup",
                        "Id": asgArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsAutoScalingAutoScalingGroup": {
                                "HealthCheckType": healthCheckType
                            }
                        }
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
                        "ISO 27001:2013 A.12.5.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            if healthCheckType != "ELB":
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{asgArn}/asg-elb-asgs-elb-healthcheck-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": asgArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Autoscaling.2] Autoscaling Groups with load balancer targets should use ELB health checks",
                    "Description": f"Autoscaling group {asgName} has ELB or ELBv2 Targets but does not use an ELB Health Check. If you attached a load balancer or target group to your Auto Scaling group, you can configure the group to mark an instance as unhealthy when Elastic Load Balancing reports it as unhealthy. If connection draining is enabled for your load balancer, Amazon EC2 Auto Scaling waits for in-flight requests to complete or the maximum timeout to expire, whichever comes first, before terminating instances due to a scaling event or health check replacement. Review the remediation section for more information on this configuration.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information about enabling ELB health checks refer to the Add Elastic Load Balancing health checks to an Auto Scaling group section of the Amazon EC2 Auto Scaling User Guide",
                            "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Compute",
                        "AssetService": "AWS Auto Scaling",
                        "AssetType": "Autoscaling Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAutoScalingAutoScalingGroup",
                            "Id": asgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsAutoScalingAutoScalingGroup": {
                                    "HealthCheckType": healthCheckType
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1"
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
                    "Id": f"{asgArn}/asg-elb-asgs-elb-healthcheck-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": asgArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Autoscaling.2] Autoscaling Groups with load balancer targets should use ELB health checks",
                    "Description": f"Autoscaling group {asgName} has ELB or ELBv2 Targets and uses an ELB Health Check.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For information about enabling ELB health checks refer to the Add Elastic Load Balancing health checks to an Auto Scaling group section of the Amazon EC2 Auto Scaling User Guide",
                            "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "AssetClass": "Compute",
                        "AssetService": "AWS Auto Scaling",
                        "AssetType": "Autoscaling Group"
                    },
                    "Resources": [
                        {
                            "Type": "AwsAutoScalingAutoScalingGroup",
                            "Id": asgArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsAutoScalingAutoScalingGroup": {
                                    "HealthCheckType": healthCheckType
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("autoscaling")
def autoscaling_high_availability_az_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Autoscaling.3] Autoscaling Groups should use at least half of a Region's Availability Zones"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Collect the open AZs in the Region
    regionalAzs = []
    for az in ec2.describe_availability_zones(AllAvailabilityZones=False)["AvailabilityZones"]:
        if (az["State"] == "available" and az["OptInStatus"] != "not-opted-in"):
            if az["ZoneName"] not in regionalAzs:
                regionalAzs.append(az["ZoneName"])
    availableAzCount = len(regionalAzs)
    for asg in describe_auto_scaling_groups(cache, session)["AutoScalingGroups"]:
        asgArn = asg["AutoScalingGroupARN"]
        asgName = asg["AutoScalingGroupName"]
        healthCheckType = asg["HealthCheckType"]
        # Check specific metadata
        asgAzs = asg["AvailabilityZones"]
        if len(asgAzs) < (availableAzCount / 2):
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{asgArn}/asg-multiaz-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": asgArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Autoscaling.3] Autoscaling Groups should use at least half of a Region's Availability Zones",
                "Description": f"Autoscaling group {asgName} does not use at least half of {awsRegion}'s {availableAzCount} available Availability Zones and only uses {len(asgAzs)}. Allowing instances to scale across more Availability Zones increases the availability and resilience of your applications in the case of unavailable resources, Availability Zone degradation, or to rapidly recover from unplanned application failures. To take advantage of the safety and reliability of geographic redundancy, span your Auto Scaling group across multiple Availability Zones within a Region and attach a load balancer to distribute incoming traffic across those Availability Zones. Review the remediation section for more information on this configuration.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about adding AZs to your ASGs refer to the Add and remove Availability Zones section of the Amazon EC2 Auto Scaling User Guide",
                        "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Compute",
                    "AssetService": "AWS Auto Scaling",
                    "AssetType": "Autoscaling Group"
                },
                "Resources": [
                    {
                        "Type": "AwsAutoScalingAutoScalingGroup",
                        "Id": asgArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsAutoScalingAutoScalingGroup": {
                                "HealthCheckType": healthCheckType
                            }
                        }
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
                        "ISO 27001:2013 A.17.2.1"
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
                "Id": f"{asgArn}/asg-multiaz-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": asgArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Autoscaling.3] Autoscaling Groups should use at least half of a Region's Availability Zones",
                "Description": f"Autoscaling group {asgName} uses at least half of {awsRegion}'s {availableAzCount} available Availability Zones by using {len(asgAzs)}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn more about adding AZs to your ASGs refer to the Add and remove Availability Zones section of the Amazon EC2 Auto Scaling User Guide",
                        "Url": "https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "AssetClass": "Compute",
                    "AssetService": "AWS Auto Scaling",
                    "AssetType": "Autoscaling Group"
                },
                "Resources": [
                    {
                        "Type": "AwsAutoScalingAutoScalingGroup",
                        "Id": asgArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsAutoScalingAutoScalingGroup": {
                                "HealthCheckType": healthCheckType
                            }
                        }
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
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding      