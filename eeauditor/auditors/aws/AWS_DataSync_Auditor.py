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
from dateutil.parser import parse

registry = CheckRegister()

datasync = boto3.client("datasync")

@registry.register_check("ec2")
def datasync_public_agent_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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

@registry.register_check("ec2")
def datasync_task_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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
                            "ProductFields": {"Product Name": "ElectricEye"},
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