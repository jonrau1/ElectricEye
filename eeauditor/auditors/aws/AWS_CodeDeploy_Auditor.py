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

from check_register import CheckRegister
import datetime
import base64
import json

registry = CheckRegister()

def get_codedeploy_deployment_groups(cache, session):
    response = cache.get("get_codedeploy_deployment_groups")
    if response:
        return response
    
    codedeploy = session.client("codedeploy")

    deploymentGroups = []

    for app in codedeploy.list_applications()["applications"]:
        # Get DGs
        for deploymentgroup in codedeploy.list_deployment_groups(applicationName=app)["deploymentGroups"]:
            # Now get the details
            deploymentGroups.append(
                    codedeploy.get_deployment_group(
                    applicationName=app,
                    deploymentGroupName=deploymentgroup
                )["deploymentGroupInfo"]
            )

    cache["get_codedeploy_deployment_groups"] = deploymentGroups
    return cache["get_codedeploy_deployment_groups"]

@registry.register_check("codedeploy")
def aws_codedeploy_deployment_group_alarms_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeDeploy.1] Amazon CodeDeploy deployment groups should enable triggering CloudWatch Alarms based on deployment criteria"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for deployment in get_codedeploy_deployment_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appName = deployment["applicationName"]
        deploymentGroupId = deployment["deploymentGroupId"]
        deploymentGroupName = deployment["deploymentGroupName"]
        deploymentGroupArn = f"arn:{awsPartition}:codedeploy:{awsRegion}:{awsAccountId}:deploymentgroup:{appName}/{deploymentGroupName}"
        deploymentConfigName = deployment["deploymentConfigName"]

        if deployment["alarmConfiguration"]["enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-enabled-alarms-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-enabled-alarms-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CodeDeploy.1] Amazon CodeDeploy deployment groups should enable triggering CloudWatch Alarms based on deployment criteria",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does not enable triggering CloudWatch Alarms based on deployment criteria. When you create or update a deployment group, you can configure a number of options to provide more control and oversight over the deployments for that deployment group. You can create a CloudWatch alarm that watches a single metric over a time period you specify and performs one or more actions based on the value of the metric relative to a given threshold over a number of time periods. For an Amazon EC2 deployment, you can create an alarm for an instance or Amazon EC2 Auto Scaling group that you are using in your CodeDeploy operations. For an AWS Lambda and an Amazon ECS deployment, you can create an alarm for errors in a Lambda function. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-enabled-alarms-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-enabled-alarms-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeDeploy.1] Amazon CodeDeploy deployment groups should enable triggering CloudWatch Alarms based on deployment criteria",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does enable triggering CloudWatch Alarms based on deployment criteria.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("codedeploy")
def aws_codedeploy_deployment_group_sns_event_notification_triggers_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeDeploy.2] Amazon CodeDeploy deployment groups should enable notifcation triggers with Amazon SNS"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for deployment in get_codedeploy_deployment_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appName = deployment["applicationName"]
        deploymentGroupId = deployment["deploymentGroupId"]
        deploymentGroupName = deployment["deploymentGroupName"]
        deploymentGroupArn = f"arn:{awsPartition}:codedeploy:{awsRegion}:{awsAccountId}:deploymentgroup:{appName}/{deploymentGroupName}"
        deploymentConfigName = deployment["deploymentConfigName"]

        if not deployment["triggerConfigurations"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-notification-triggers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-notification-triggers-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[CodeDeploy.2] Amazon CodeDeploy deployment groups should enable notifcation triggers with Amazon SNS",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does not enable notifcation triggers with Amazon SNS. You can add triggers to a CodeDeploy deployment group to receive notifications about events related to deployments or instances in that deployment group. These notifications are sent to recipients who are subscribed to an Amazon SNS topic you have made part of the trigger's action. You can receive notifications for CodeDeploy events in SMS messages or email messages. You can also use the JSON data that is created when a specified event occurs in other ways, such as sending messages to Amazon SQS queues or invoking a function in AWS Lambda. You might choose to use triggers to receive notifications if: you are a developer who needs to know when a deployment fails or stops so you can troubleshoot it or are a manager who wants an at-a-glance count of deployment and instance events. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-notification-triggers-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-notification-triggers-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeDeploy.2] Amazon CodeDeploy deployment groups should enable notifcation triggers with Amazon SNS",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does enable notifcation triggers with Amazon SNS.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("codedeploy")
def aws_codedeploy_deployment_group_autorollback_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeDeploy.3] Amazon CodeDeploy deployment groups should enable automatic deployment rollbacks"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for deployment in get_codedeploy_deployment_groups(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(deployment,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appName = deployment["applicationName"]
        deploymentGroupId = deployment["deploymentGroupId"]
        deploymentGroupName = deployment["deploymentGroupName"]
        deploymentGroupArn = f"arn:{awsPartition}:codedeploy:{awsRegion}:{awsAccountId}:deploymentgroup:{appName}/{deploymentGroupName}"
        deploymentConfigName = deployment["deploymentConfigName"]

        if not deployment["triggerConfigurations"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-autorollback-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-autorollback-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CodeDeploy.3] Amazon CodeDeploy deployment groups should enable automatic deployment rollbacks",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does not enable automatic deployment rollbacks. You can configure a deployment group or deployment to automatically roll back when a deployment fails or when a monitoring threshold you specify is met. In this case, the last known good version of an application revision is deployed. You can configure optional settings for a deployment group when you use the console to create an application, create a deployment group, or update a deployment group. When you create a new deployment, you can also choose to override the automatic rollback configuration that were specified for the deployment group.  Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{deploymentGroupArn}/codedeploy-deploymentgroup-autorollback-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{deploymentGroupArn}/codedeploy-deploymentgroup-autorollback-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeDeploy.3] Amazon CodeDeploy deployment groups should enable automatic deployment rollbacks",
                "Description": f"Amazon CodeDeploy deployment group {deploymentGroupName} in CodeDeploy Application {appName} does enable automatic deployment rollbacks.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to different types of alarming, notification, and rollback tactics for your CodeDeploy Deployment Groups refer to the Configure advanced options for a deployment group section of the AWS CodeDeploy User Guide",
                        "Url": "https://docs.aws.amazon.com/codedeploy/latest/userguide/deployment-groups-configure-advanced-options.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeDeploy",
                    "AssetComponent": "Deployment Group"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeDeployDeploymentGroup",
                        "Id": deploymentGroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "DeploymentGroupId": deploymentGroupId,
                                "DeploymentGroupName": deploymentGroupName,
                                "DeploymentConfigName": deploymentConfigName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??