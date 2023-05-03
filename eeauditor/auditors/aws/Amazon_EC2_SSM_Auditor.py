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
from dateutil.parser import parse
from botocore.config import Config
import base64
import json
# Adding backoff and retries for SSM - this API gets throttled a lot
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'adaptive'
   }
)

registry = CheckRegister()

def paginate(cache, session):
    ec2 = session.client("ec2",config=config)

    instanceList = []
    response = cache.get("instances")
    if response:
        return response
    paginator = ec2.get_paginator("describe_instances")
    if paginator:
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name','Values': ['running']}]):
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    instanceList.append(i)
        cache["instances"] = instanceList
        return cache["instances"]

@registry.register_check("ec2")
def ec2_instance_ssm_managed_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.SystemsManager.1] Running EC2 instances should be managed by Systems Manager"""
    ssm = session.client("ssm",config=config)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in paginate(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        response = ssm.describe_instance_information(
            Filters=[
                {
                    'Key': 'InstanceIds',
                    'Values': [instanceId]
                }
            ]
        )["InstanceInformationList"]
        # this is a failing check
        if not response:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-managed-by-ssm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EC2.SystemsManager.1] Running EC2 instances should be managed by Systems Manager",
                "Description": f"EC2 Instance {instanceId} is not managed by AWS Systems Manager. Systems Manager enables automated activities such as patching, configuration management, software inventory management and more. Not having instances managed by Systems Manager can degrade the effectiveness of important security processes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-managed-by-ssm-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.SystemsManager.1] Running EC2 instances should be managed by Systems Manager",
                "Description": f"EC2 Instance {instanceId} is managed by AWS Systems Manager.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To learn how to configure Systems Manager and associated instances refer to the Setting Up AWS Systems Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/en_us/systems-manager/latest/userguide/systems-manager-setting-up.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
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

@registry.register_check("ec2")
def ssm_instace_agent_update_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.SystemsManager.2] EC2 Linux Instances managed by Systems Manager should have the latest SSM Agent installed"""
    ssm = session.client("ssm",config=config)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in paginate(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        r = ssm.describe_instance_information(
            Filters=[
                {
                    'Key': 'InstanceIds',
                    'Values': [instanceId]
                }
            ]
        )["InstanceInformationList"]
        if not r:
            continue
        else:
            for x in r:
                if str(x['PlatformType']) != 'Linux':
                    continue
                else:
                    if str(x["IsLatestVersion"]) == "False":
                        # this is a failing check
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": instanceArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "LOW"},
                            "Confidence": 99,
                            "Title": "[EC2.SystemsManager.2] EC2 Linux Instances managed by Systems Manager should have the latest SSM Agent installed",
                            "Description": f"EC2 Instance {instanceId} is a Linux-based platform which does not have the latest SSM Agent installed. Not having the latest SSM Agent can lead to issues with patching, configuration management, inventory management, and/or vulnerability management activities. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Compute",
                                "AssetService": "Amazon EC2",
                                "AssetComponent": "Instance"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsEc2Instance",
                                    "Id": instanceArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEc2Instance": {
                                            "Type": instanceType,
                                            "ImageId": instanceImage,
                                            "VpcId": vpcId,
                                            "SubnetId": subnetId,
                                            "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 ID.AM-2",
                                    "NIST SP 800-53 Rev. 4 CM-8",
                                    "NIST SP 800-53 Rev. 4 PM-5",
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
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": instanceArn + "/ec2-ssm-agent-latest-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": instanceArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[EC2.SystemsManager.2] EC2 Linux Instances managed by Systems Manager should have the latest SSM Agent installed",
                            "Description": f"EC2 Instance {instanceId} is a Linux-based platform and has the latest SSM Agent installed.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For information on automating updates to the SSM Agent refer to the Automate Updates to SSM Agent section of the AWS Systems Manager User Guide",
                                    "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Compute",
                                "AssetService": "Amazon EC2",
                                "AssetComponent": "Instance"
                            },
                            "Resources": [
                                {
                                    "Type": "AwsEc2Instance",
                                    "Id": instanceArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsEc2Instance": {
                                            "Type": instanceType,
                                            "ImageId": instanceImage,
                                            "VpcId": vpcId,
                                            "SubnetId": subnetId,
                                            "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 ID.AM-2",
                                    "NIST SP 800-53 Rev. 4 CM-8",
                                    "NIST SP 800-53 Rev. 4 PM-5",
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

@registry.register_check("ec2")
def ssm_instance_association_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.SystemsManager.3] Running EC2 instances managed by Systems Manager should have a successful Association status"""
    ssm = session.client("ssm",config=config)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in paginate(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        r = ssm.describe_instance_information(
            Filters=[
                {
                    'Key': 'InstanceIds',
                    'Values': [instanceId]
                }
            ]
        )["InstanceInformationList"]
        if not r:
            continue
        else:
            for x in r:
                associationStatusCheck = str(x["AssociationStatus"])
                if associationStatusCheck != "Success":
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-association-success-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "LOW"},
                        "Confidence": 99,
                        "Title": "[EC2.SystemsManager.3] Running EC2 instances managed by Systems Manager should have a successful Association status",
                        "Description": f"EC2 Instance {instanceId} has failed its last Systems Manager State Manager Association. Associations are State Manager automation constructs which encapsulate execution of SSM Documents such as Patching, software configuration, and SSM Agent updates onto an instance. A failed Association can represent the failure of a critical process and should be reviewed. Refer to the remediation instructions for more information on working with State Manager Associations.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Amazon EC2",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": vpcId,
                                        "SubnetId": subnetId,
                                        "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.AM-2",
                                "NIST SP 800-53 Rev. 4 CM-8",
                                "NIST SP 800-53 Rev. 4 PM-5",
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
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-ssm-association-success-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[EC2.SystemsManager.3] Running EC2 instances managed by Systems Manager should have a successful Association status",
                        "Description": f"EC2 Instance {instanceId} has passed its last Systems Manager State Manager Association.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For information on Systems Manager Associations refer to the Working with Associations in Systems Manager section of the AWS Systems Manager User Guide",
                                "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-associations.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Amazon EC2",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": vpcId,
                                        "SubnetId": subnetId,
                                        "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 ID.AM-2",
                                "NIST SP 800-53 Rev. 4 CM-8",
                                "NIST SP 800-53 Rev. 4 PM-5",
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

@registry.register_check("ec2")
def ssm_instance_patch_state_state(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EC2.SystemsManager.4] Running EC2 instances managed by Systems Manager should have the latest patches installed by Patch Manager"""
    ssm = session.client("ssm",config=config)
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for i in paginate(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(i,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        instanceId = str(i["InstanceId"])
        instanceArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
        instanceType = str(i["InstanceType"])
        instanceImage = str(i["ImageId"])
        subnetId = str(i["SubnetId"])
        vpcId = str(i["VpcId"])
        try:
            instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
        except KeyError:
            instanceLaunchedAt = str(i["LaunchTime"])
        # Check specific metadata
        r = ssm.describe_instance_patches(InstanceId=instanceId)              
        if not r["Patches"]:
            # This is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-patch-manager-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EC2.SystemsManager.4] Running EC2 instances managed by Systems Manager should have the latest patches installed by Patch Manager",
                "Description": f"EC2 Instance {instanceId} does not have any patch information recorded and is likely not managed by Patch Manager. Patch Manager automates the installation and application of security, performance, and major version upgrades and KBs onto your instances, reducing exposure to vulnerabilities and other weaknesses. Without automatic patching at scale, vulnerabilities can quickly manifest within a given cloud environment leading to potential avenues of attack for adversaries and other unauthorized actors. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": instanceArn + "/ec2-patch-manager-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": instanceArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EC2.SystemsManager.4] Running EC2 instances managed by Systems Manager should have the latest patches installed by Patch Manager",
                "Description": f"EC2 Instance {instanceId} has patches applied by AWS Systems Manager Patch Manager. You should still review Patch Compliance information to ensure that all required patches were successfully applied.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on Patch Manager refer to the AWS Systems Manager Patch Manager section of the AWS Systems Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Compute",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Instance"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Instance",
                        "Id": instanceArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Instance": {
                                "Type": instanceType,
                                "ImageId": instanceImage,
                                "VpcId": vpcId,
                                "SubnetId": subnetId,
                                "LaunchedAt": parse(instanceLaunchedAt).isoformat()
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-2",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 PM-5",
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