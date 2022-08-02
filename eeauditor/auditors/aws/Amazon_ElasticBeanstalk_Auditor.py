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
import json
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
ec2 = boto3.client("ec2")
elasticbeanstalk = boto3.client("elasticbeanstalk")

# loop through EBS volumes
def describe_environments(cache):
    response = cache.get("describe_environments")
    if response:
        return response
    cache["describe_environments"] = elasticbeanstalk.describe_environments()
    return cache["describe_environments"]

@registry.register_check("elasticbeanstalk")
def ebs_volume_attachment_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.1] EBS Volumes should be in an attached state"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for envs in describe_environments(cache)["Environments"]:
        envName = envs["EnvironmentName"]
        appName = envs["ApplicationName"]
        r = elasticbeanstalk.describe_configuration_settings(
            ApplicationName=appName,
            EnvironmentName=envName
        )
        

        response = elasticbeanstalk.describe_configuration_options(
            #ApplicationName='string',
            #TemplateName='string',
            EnvironmentName=envName,
            #SolutionStackName='string',
            #PlatformArn='string',
            Options=[
                {
                    'Namespace': 'aws:autoscaling:launchconfiguration',
                    'OptionName': 'DisableIMDSv1'
                },
            ]
        )

        print(
            json.dumps(
                response,
                indent=4,
                default=str
            )
        )

'''
@registry.register_check("ec2")
def ebs_volume_attachment_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.1] EBS Volumes should be in an attached state"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for volumes in describe_volumes(cache)["Volumes"]:
        ebsVolumeId = str(volumes["VolumeId"])
        ebsVolumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}/{ebsVolumeId}"
        ebsAttachments = volumes["Attachments"]
        for attachments in ebsAttachments:
            ebsAttachmentState = str(attachments["State"])    
            if ebsAttachmentState != "attached":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": ebsVolumeArn + "/ebs-volume-attachment-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": ebsVolumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EBS.1] EBS Volumes should be in an attached state",
                    "Description": "EBS Volume "
                    + ebsVolumeId
                    + " is not in an attached state. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": ebsVolumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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
                    "Id": ebsVolumeArn + "/ebs-volume-attachment-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": ebsVolumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EBS.1] EBS Volumes should be in an attached state",
                    "Description": "EBS Volume " + ebsVolumeId + " is in an attached state.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": ebsVolumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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
'''