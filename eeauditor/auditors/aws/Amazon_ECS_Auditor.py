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

# import boto3 clients
ecs = boto3.client("ecs")
# loop through ECS Clusters
def list_clusters(cache):
    response = cache.get("list_clusters")
    if response:
        return response
    cache["list_clusters"] = ecs.list_clusters()
    return cache["list_clusters"]

"""def list_active_task_definitions(cache):
    response = cache.get("")"""

@registry.register_check("ecs")
def ecs_cluster_container_insights_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECS.1] ECS clusters should have container insights enabled"""
    response = list_clusters(cache)
    myEcsClusters = response["clusterArns"]
    for clusters in myEcsClusters:
        clusterArn = str(clusters)
        try:
            response = ecs.describe_clusters(clusters=[clusterArn])
            for clusterinfo in response["clusters"]:
                clusterName = str(clusterinfo["clusterName"])
                ecsClusterArn = str(clusterinfo["clusterArn"])
                for settings in clusterinfo["settings"]:
                    contInsightsCheck = str(settings["value"])
                    # ISO Time
                    iso8601Time = (
                        datetime.datetime.utcnow()
                        .replace(tzinfo=datetime.timezone.utc)
                        .isoformat()
                    )
                    if contInsightsCheck == "disabled":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": ecsClusterArn + "/ecs-cluster-container-insights-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": ecsClusterArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[ECS.1] ECS clusters should have container insights enabled",
                            "Description": "ECS cluster "
                            + clusterName
                            + " does not have container insights enabled. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on configuring Container Insights for your cluster refer to the Setting Up Container Insights on Amazon ECS for Cluster- and Service-Level Metrics section of the Amazon CloudWatch User Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/deploy-container-insights-ECS-cluster.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEcsCluster",
                                    "Id": ecsClusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"ClusterName": clusterName}},
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
                            "Id": ecsClusterArn + "/ecs-cluster-container-insights-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": ecsClusterArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ECS.1] ECS clusters should have container insights enabled",
                            "Description": "ECS cluster "
                            + clusterName
                            + " has container insights enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on configuring Container Insights for your cluster refer to the Setting Up Container Insights on Amazon ECS for Cluster- and Service-Level Metrics section of the Amazon CloudWatch User Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/deploy-container-insights-ECS-cluster.html",
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEcsCluster",
                                    "Id": ecsClusterArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {"Other": {"ClusterName": clusterName}},
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
        except Exception as e:
            print(e)

@registry.register_check("ecs")
def ecs_cluster_default_provider_strategy_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECS.2] ECS clusters should have a default cluster capacity provider strategy configured"""
    response = list_clusters(cache)
    myEcsClusters = response["clusterArns"]
    for clusters in myEcsClusters:
        clusterArn = str(clusters)
        try:
            response = ecs.describe_clusters(clusters=[clusterArn])
            for clusterinfo in response["clusters"]:
                clusterName = str(clusterinfo["clusterName"])
                ecsClusterArn = str(clusterinfo["clusterArn"])
                defaultProviderStratCheck = str(clusterinfo["defaultCapacityProviderStrategy"])
                # ISO Time
                iso8601Time = (
                    datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                )
                if defaultProviderStratCheck == "[]":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": ecsClusterArn + "/ecs-cluster-default-provider-strategy-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": ecsClusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ECS.2] ECS clusters should have a default cluster capacity provider strategy configured",
                        "Description": "ECS cluster "
                        + clusterName
                        + " does not have a default provider strategy configured. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on cluster capacity provider strategies for your cluster refer to the Amazon ECS Cluster Capacity Providers section of the Amazon Elastic Container Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cluster-capacity-providers.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEcsCluster",
                                "Id": ecsClusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ClusterName": clusterName}},
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
                        "Id": ecsClusterArn + "/ecs-cluster-default-provider-strategy-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": ecsClusterArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ECS.2] ECS clusters should have a default cluster capacity provider strategy configured",
                        "Description": "ECS cluster "
                        + clusterName
                        + " has a default provider strategy configured.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on cluster capacity provider strategies for your cluster refer to the Amazon ECS Cluster Capacity Providers section of the Amazon Elastic Container Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cluster-capacity-providers.html",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEcsCluster",
                                "Id": ecsClusterArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {"ClusterName": clusterName}},
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
        except Exception as e:
            print(e)

@registry.register_check("ecs")
def ecs_task_definition_privileged_container_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECS.3] ECS Task Definitions should not run privileged containers if not required"""
    for taskdef in ecs.list_task_definitions(status='ACTIVE')['taskDefinitionArns']:
        try:
            response = ecs.describe_task_definition(taskDefinition=taskdef)["taskDefinition"]
            taskDefinitionArn = str(response['taskDefinitionArn'])
            tdefFamily = str(response["family"])
            # Loop container definitions 
            for cdef in response["containerDefinitions"]:
                # ISO Time
                iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
                cdefName = str(cdef["name"])
                # We are going to assume that if there is not a privileged flag...that it is ;)
                try:
                    privCheck = str(cdef["privileged"])
                except:
                    privCheck = 'UNKNOWN'
                if privCheck != 'False': 
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": taskDefinitionArn + "/" + cdefName + "/ecs-task-definition-privileged-container-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": taskDefinitionArn + "/" + cdefName,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "TTPs/Privilege Escalation"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[ECS.3] ECS Task Definitions should not run privileged containers if not required",
                        "Description": "ECS Container Definition "
                        + cdefName
                        + " in Task Definition "
                        + taskDefinitionArn
                        + " has defined a Privileged container, which should be avoided unless absolutely necessary. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "Containers running as Privileged will have Root permissions, this should be avoided if not needed. Refer to the Task definition parameters Security section of the Amazon Elastic Container Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEcsTaskDefinition",
                                "Id": taskDefinitionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEcsTaskDefinition": {
                                        "ContainerDefinitions": [
                                            {
                                                "Name": cdefName
                                            }
                                        ],
                                        "Family": tdefFamily
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-1",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-2",
                                "NIST SP 800-53 IA-1",
                                "NIST SP 800-53 IA-2",
                                "NIST SP 800-53 IA-3",
                                "NIST SP 800-53 IA-4",
                                "NIST SP 800-53 IA-5",
                                "NIST SP 800-53 IA-6",
                                "NIST SP 800-53 IA-7",
                                "NIST SP 800-53 IA-8",
                                "NIST SP 800-53 IA-9",
                                "NIST SP 800-53 IA-10",
                                "NIST SP 800-53 IA-11",
                                "AICPA TSC CC6.1",
                                "AICPA TSC CC6.2",
                                "ISO 27001:2013 A.9.2.1",
                                "ISO 27001:2013 A.9.2.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.2.4",
                                "ISO 27001:2013 A.9.2.6",
                                "ISO 27001:2013 A.9.3.1",
                                "ISO 27001:2013 A.9.4.2",
                                "ISO 27001:2013 A.9.4.3"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": taskDefinitionArn + "/" + cdefName + "/ecs-task-definition-privileged-container-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": taskDefinitionArn + "/" + cdefName,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "TTPs/Privilege Escalation"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[ECS.3] ECS Task Definitions should not run privileged containers if not required",
                        "Description": "ECS Container Definition "
                        + cdefName
                        + " in Task Definition "
                        + taskDefinitionArn
                        + " has not defined a Privileged container.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "Containers running as Privileged will have Root permissions, this should be avoided if not needed. Refer to the Task definition parameters Security section of the Amazon Elastic Container Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsEcsTaskDefinition",
                                "Id": taskDefinitionArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEcsTaskDefinition": {
                                        "ContainerDefinitions": [
                                            {
                                                "Name": cdefName
                                            }
                                        ],
                                        "Family": tdefFamily
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-1",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-2",
                                "NIST SP 800-53 IA-1",
                                "NIST SP 800-53 IA-2",
                                "NIST SP 800-53 IA-3",
                                "NIST SP 800-53 IA-4",
                                "NIST SP 800-53 IA-5",
                                "NIST SP 800-53 IA-6",
                                "NIST SP 800-53 IA-7",
                                "NIST SP 800-53 IA-8",
                                "NIST SP 800-53 IA-9",
                                "NIST SP 800-53 IA-10",
                                "NIST SP 800-53 IA-11",
                                "AICPA TSC CC6.1",
                                "AICPA TSC CC6.2",
                                "ISO 27001:2013 A.9.2.1",
                                "ISO 27001:2013 A.9.2.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.2.4",
                                "ISO 27001:2013 A.9.2.6",
                                "ISO 27001:2013 A.9.3.1",
                                "ISO 27001:2013 A.9.4.2",
                                "ISO 27001:2013 A.9.4.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
        except Exception as e:
            print(e)

@registry.register_check("ecs")
def ecs_task_definition_security_labels_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECS.4] ECS Task Definitions for EC2 should have Docker Security Options (SELinux or AppArmor) configured"""
    for taskdef in ecs.list_task_definitions(status='ACTIVE')['taskDefinitionArns']:
        try:
            response = ecs.describe_task_definition(taskDefinition=taskdef)["taskDefinition"]
            taskDefinitionArn = str(response["taskDefinitionArn"])
            tdefFamily = str(response["family"])
            # If there is a network mode of "awsvpc" it is likely a Fargate task - even though EC2 compute can run with that...
            # time for some funky edge cases, keep that in mind before you yeet an issue at me, please ;)
            if str(response["networkMode"]) == 'awsvpc':
                continue
            else:
                # Loop container definitions 
                for cdef in response["containerDefinitions"]:
                    # ISO Time
                    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
                    cdefName = str(cdef["name"])
                    try:
                        # This is a passing check
                        secOpts = str(cdef["dockerSecurityOptions"])
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": taskDefinitionArn + "/" + cdefName + "/ecs-task-definition-security-labels-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": taskDefinitionArn + "/" + cdefName,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ECS.4] ECS Task Definitions for EC2 should have Docker Security Options (SELinux or AppArmor) configured",
                            "Description": "ECS Container Definition "
                            + cdefName
                            + " in Task Definition "
                            + taskDefinitionArn
                            + " has Docker Security Options configured.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "Containers running on EC2 Compute-types should have Docker Security Options configured. Refer to the Task definition parameters Security section of the Amazon Elastic Container Service Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEcsTaskDefinition",
                                    "Id": taskDefinitionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEcsTaskDefinition": {
                                            "ContainerDefinitions": [
                                                {
                                                    "Name": cdefName
                                                }
                                            ],
                                            "Family": tdefFamily
                                        }
                                    }
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
                                    "ISO 27001:2013 A.14.2.4",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    except:
                        secOpts = str('["NO_OPTIONS"]')
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": taskDefinitionArn + "/" + cdefName + "/ecs-task-definition-security-labels-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": taskDefinitionArn + "/" + cdefName,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[ECS.4] ECS Task Definitions for EC2 should have Docker Security Options (SELinux or AppArmor) configured",
                            "Description": "ECS Container Definition "
                            + cdefName
                            + " in Task Definition "
                            + taskDefinitionArn
                            + " does not have any Docker Security Options configured. Refer to the remediation instructions to remediate this behavior",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "Containers running on EC2 Compute-types should have Docker Security Options configured. Refer to the Task definition parameters Security section of the Amazon Elastic Container Service Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsEcsTaskDefinition",
                                    "Id": taskDefinitionArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEcsTaskDefinition": {
                                            "ContainerDefinitions": [
                                                {
                                                    "Name": cdefName
                                                }
                                            ],
                                            "Family": tdefFamily
                                        }
                                    }
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
                                    "ISO 27001:2013 A.14.2.4",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
        except Exception as e:
            print(e)