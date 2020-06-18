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
ecs = boto3.client("ecs")
# loop through ECS Clusters
def list_clusters(cache):
    response = cache.get("list_clusters")
    if response:
        return response
    cache["list_clusters"] = ecs.list_clusters()
    return cache["list_clusters"]


@registry.register_check("ecs")
def ecs_cluster_container_insights_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
def ecs_cluster_default_provider_strategy_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
