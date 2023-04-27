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

@registry.register_check("datasync")
def datasync_public_agent_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DataSync.1] AWS DataSync Agents should not be accessible over the Internet"""
    datasync = session.client("datasync")
    paginator = datasync.get_paginator("list_agents")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginator.paginate()
        for page in iterator:
            for a in page["Agents"]:
                agentArn = str(a["AgentArn"])
                agentName = str(a["Name"])
                response = datasync.describe_agent(AgentArn=agentArn)
                if str(response["EndpointType"]) == "PUBLIC":
                    try:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": agentArn + "/public-agent-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": agentArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[DataSync.1] AWS DataSync Agents should not be accessible over the Internet",
                            "Description": "DataSync Agent "
                            + agentName
                            + " is not configured to use a PrivateLink Endpoint. If you use a VPC endpoint, all communication from DataSync to AWS services occurs through the VPC endpoint in your VPC in AWS. This approach provides a private connection between your self-managed data center, your VPC, and AWS services. It increases the security of your data as it is copied over the network. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "You CANNOT change and Endpoint Type after creation and will need to create a new Agent. To learn more about making an Agent private refer to the Choose a service endpoint section of the AWS DataSync User Guide",
                                    "Url": "https://docs.aws.amazon.com/datasync/latest/userguide/choose-service-endpoint.html#choose-service-endpoint-vpc"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Migration & Transfer",
                                "AssetService": "AWS DataSync",
                                "AssetType": "Agent"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsDataSyncAgent",
                                    "Id": agentArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "Name": agentName
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    except Exception as e:
                        print(e)
                        continue
                else:
                    try:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": agentArn + "/public-agent-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": agentArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[DataSync.1] AWS DataSync Agents should not be accessible over the Internet",
                            "Description": "DataSync Agent "
                            + agentName
                            + " is configured to use a PrivateLink Endpoint.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "You CANNOT change and Endpoint Type after creation and will need to create a new Agent. To learn more about making an Agent private refer to the Choose a service endpoint section of the AWS DataSync User Guide",
                                    "Url": "https://docs.aws.amazon.com/datasync/latest/userguide/choose-service-endpoint.html#choose-service-endpoint-vpc"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Migration & Transfer",
                                "AssetService": "AWS DataSync",
                                "AssetType": "Agent"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsDataSyncAgent",
                                    "Id": agentArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "Name": agentName
                                        }
                                    },
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 PR.AC-3",
                                    "NIST SP 800-53 Rev. 4 AC-1",
                                    "NIST SP 800-53 Rev. 4 AC-17",
                                    "NIST SP 800-53 Rev. 4 AC-19",
                                    "NIST SP 800-53 Rev. 4 AC-20",
                                    "NIST SP 800-53 Rev. 4 SC-15",
                                    "AICPA TSC CC6.6",
                                    "ISO 27001:2013 A.6.2.1",
                                    "ISO 27001:2013 A.6.2.2",
                                    "ISO 27001:2013 A.11.2.6",
                                    "ISO 27001:2013 A.13.1.1",
                                    "ISO 27001:2013 A.13.2.1",
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    except Exception as e:
                        print(e)
                        continue
            else:
                continue
    except Exception as e:
        print(e)

@registry.register_check("datasync")
def datasync_task_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[DataSync.2] AWS DataSync data transfer Tasks should have logging enabled"""
    datasync = session.client("datasync")
    paginator = datasync.get_paginator("list_tasks")
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    try:
        iterator = paginator.paginate()
        for page in iterator:
            for t in page["Tasks"]:
                taskArn = str(t["TaskArn"])
                taskName = str(t["Name"])
                response = datasync.describe_task(TaskArn=taskArn)
                if str(response["EndpointType"]) == "PUBLIC":
                    try:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": taskArn + "/task-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": taskArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[DataSync.2] AWS DataSync data transfer Tasks should have logging enabled",
                            "Description": "DataSync Task "
                            + taskName
                            + " does not have logging enabled. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about monitoring DataSync Tasks refer to the Monitoring your task section of the AWS DataSync User Guide",
                                    "Url": "https://docs.aws.amazon.com/datasync/latest/userguide/monitor-datasync.html"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Migration & Transfer",
                                "AssetService": "AWS DataSync",
                                "AssetType": "Task"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsDataSyncTask",
                                    "Id": taskArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "Name": taskName
                                        }
                                    },
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
                                    "ISO 27001:2013 A.16.1.7",
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    except Exception as e:
                        print(e)
                        continue
                else:
                    try:
                        # create Sec Hub finding
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": taskArn + "/task-logging-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": taskArn,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/AWS Security Best Practices",
                                "Effects/Data Exposure"
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[DataSync.2] AWS DataSync data transfer Tasks should have logging enabled",
                            "Description": "DataSync Task "
                            + taskName
                            + " has logging enabled.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To learn more about monitoring DataSync Tasks refer to the Monitoring your task section of the AWS DataSync User Guide",
                                    "Url": "https://docs.aws.amazon.com/datasync/latest/userguide/monitor-datasync.html"
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "AssetClass": "Migration & Transfer",
                                "AssetService": "AWS DataSync",
                                "AssetType": "Task"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsDataSyncTask",
                                    "Id": taskArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Other": {
                                            "Name": taskName
                                        }
                                    },
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
                                    "ISO 27001:2013 A.16.1.7",
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
                    except Exception as e:
                        print(e)
                        continue
            else:
                continue
    except Exception as e:
        print(e)