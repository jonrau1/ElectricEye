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

def describe_workspaces(cache, session):
    workspaces = session.client("workspaces")
    response = cache.get("describe_workspaces", [])
    if response:
        return response
    cache["describe_workspaces"] = workspaces.describe_workspaces()
    return cache["describe_workspaces"]

@registry.register_check("workspaces")
def workspaces_user_volume_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WorkSpaces.1] WorkSpaces should have user volume encryption enabled"""
    work = describe_workspaces(cache, session)
    for workspace in work["Workspaces"]:
        workspaceId = str(workspace["WorkspaceId"])
        workspaceArn = (
            f"arn:{awsPartition}:workspaces:{awsRegion}:{awsAccountId}:workspace/{workspaceId}"
        )
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        try:
            userVolumeEncryptionCheck = str(
                workspace["UserVolumeEncryptionEnabled"])
            if userVolumeEncryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": workspaceArn + "/workspaces-user-volume-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": workspaceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[WorkSpaces.1] WorkSpaces should have user volume encryption enabled",
                    "Description": "Workspace "
                    + workspaceId
                    + " does not have user volume encryption enabled. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide",
                            "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWorkspacesWorkspace",
                            "Id": workspaceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"WorkspaceId": workspaceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": workspaceArn + "/workspaces-user-volume-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": workspaceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[WorkSpaces.1] WorkSpaces should have user volume encryption enabled",
                    "Description": "Workspace "
                    + workspaceId
                    + " has user volume encryption enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide",
                            "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWorkspacesWorkspace",
                            "Id": workspaceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"WorkspaceId": workspaceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("workspaces")
def workspaces_root_volume_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WorkSpaces.2] WorkSpaces should have root volume encryption enabled"""
    work = describe_workspaces(cache, session)
    for workspace in work["Workspaces"]:
        workspaceId = str(workspace["WorkspaceId"])
        workspaceArn = (
            f"arn:{awsPartition}:workspaces:{awsRegion}:{awsAccountId}:workspace/{workspaceId}"
        )
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        try:
            rootVolumeEncryptionCheck = str(
                workspace["RootVolumeEncryptionEnabled"])
            if rootVolumeEncryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": workspaceArn + "/workspaces-root-volume-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": workspaceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[WorkSpaces.2] WorkSpaces should have root volume encryption enabled",
                    "Description": "Workspace "
                    + workspaceId
                    + " does not have root volume encryption enabled. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide",
                            "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWorkspacesWorkspace",
                            "Id": workspaceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"WorkspaceId": workspaceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": workspaceArn + "/workspaces-root-volume-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": workspaceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[WorkSpaces.2] WorkSpaces should have root volume encryption enabled",
                    "Description": "Workspace "
                    + workspaceId
                    + " does not have root volume encryption enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on WorkSpaces encryption and how to configure it refer to the Encrypted WorkSpaces section of the Amazon WorkSpaces Administrator Guide",
                            "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsWorkspacesWorkspace",
                            "Id": workspaceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"WorkspaceId": workspaceId}},
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.DS-1",
                            "NIST SP 800-53 MP-8",
                            "NIST SP 800-53 SC-12",
                            "NIST SP 800-53 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
        except Exception as e:
            print(e)

@registry.register_check("workspaces")
def workspaces_running_mode_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WorkSpaces.3] WorkSpaces should be configured to auto stop after inactivity"""
    work = describe_workspaces(cache, session)
    for workspace in work["Workspaces"]:
        workspaceId = str(workspace["WorkspaceId"])
        workspaceArn = (
            f"arn:{awsPartition}:workspaces:{awsRegion}:{awsAccountId}:workspace/{workspaceId}"
        )
        runningModeCheck = str(workspace["WorkspaceProperties"]["RunningMode"])
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        if runningModeCheck != "AUTO_STOP":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": workspaceArn + "/workspaces-auto-stop-running-mode-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[WorkSpaces.3] WorkSpaces should be configured to auto stop after inactivity",
                "Description": "Workspace "
                + workspaceId
                + " does not have its running mode configured to auto-stop. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WorkSpaces running modes and how to auto-stop refer to the Manage the WorkSpace Running Mode section of the Amazon WorkSpaces Administrator Guide",
                        "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/running-mode.html#stop-start-workspace",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWorkspacesWorkspace",
                        "Id": workspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"WorkspaceId": workspaceId}},
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
                "Id": workspaceArn + "/workspaces-auto-stop-running-mode-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workspaceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WorkSpaces.3] WorkSpaces should be configured to auto stop after inactivity",
                "Description": "Workspace "
                + workspaceId
                + " has its running mode configured to auto-stop.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WorkSpaces running modes and how to auto-stop refer to the Manage the WorkSpace Running Mode section of the Amazon WorkSpaces Administrator Guide",
                        "Url": "https://docs.aws.amazon.com/workspaces/latest/adminguide/running-mode.html#stop-start-workspace",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsWorkspacesWorkspace",
                        "Id": workspaceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"WorkspaceId": workspaceId}},
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

@registry.register_check("workspaces")
def workspaces_directory_default_internet_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[WorkSpaces.4] WorkSpaces Directories should not be configured to provide default internet access"""
    workspaces = session.client("workspaces")
    response = workspaces.describe_workspace_directories()
    for directory in response["Directories"]:
        workspacesDirectoryId = str(directory["DirectoryId"])
        workspacesDirectoryArn = f"arn:{awsPartition}:workspaces:{awsRegion}:{awsAccountId}:directory/{workspacesDirectoryId}"
        internetAccessCheck = str(
            directory["WorkspaceCreationProperties"]["EnableInternetAccess"])
        iso8601Time = datetime.datetime.utcnow().replace(
            tzinfo=datetime.timezone.utc).isoformat()
        if internetAccessCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": workspacesDirectoryArn
                + "/workspaces-directory-default-internet-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workspacesDirectoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[WorkSpaces.4] WorkSpaces Directories should not be configured to provide default internet access",
                "Description": "Workspace directory "
                + workspacesDirectoryId
                + " provides default internet access to WorkSpaces. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WorkSpaces internet access refer to the Provide Internet Access from Your WorkSpace section of the Amazon WorkSpaces Administrator Guide",
                        "Url": "https://docs.amazonaws.cn/en_us/workspaces/latest/adminguide/amazon-workspaces-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": workspacesDirectoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"DirectoryId": workspacesDirectoryId}},
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
                "Id": workspacesDirectoryArn
                + "/workspaces-directory-default-internet-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workspacesDirectoryArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[WorkSpaces.4] WorkSpaces Directories should not be configured to provide default internet access",
                "Description": "Workspace directory "
                + workspacesDirectoryId
                + " does not provide default internet access to WorkSpaces.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on WorkSpaces internet access refer to the Provide Internet Access from Your WorkSpace section of the Amazon WorkSpaces Administrator Guide",
                        "Url": "https://docs.amazonaws.cn/en_us/workspaces/latest/adminguide/amazon-workspaces-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": workspacesDirectoryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"DirectoryId": workspacesDirectoryId}},
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