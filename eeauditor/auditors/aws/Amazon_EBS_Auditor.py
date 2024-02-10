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
import base64
import json

registry = CheckRegister()

def describe_volumes(cache, session):
    response = cache.get("describe_volumes")
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_volumes"] = ec2.describe_volumes(
        DryRun=False,
        MaxResults=500,
        Filters=[{"Name": "status", "Values": ["available", "in-use"]}]
    )["Volumes"]
    return cache["describe_volumes"]

def describe_snapshots(cache, session, awsAccountId):
    response = cache.get("describe_snapshots")
    if response:
        return response
    
    ec2 = session.client("ec2")

    cache["describe_snapshots"] = ec2.describe_snapshots(OwnerIds=[awsAccountId], DryRun=False)["Snapshots"]
    return cache["describe_snapshots"]

def describe_images(cache, session, awsAccountId):
    response = cache.get("describe_images")
    if response:
        return response
    
    ec2 = session.client("ec2")
    
    cache["describe_images"] = ec2.describe_images(
        Filters=[{"Name": "owner-id", "Values": [awsAccountId]}], DryRun=False
    )["Images"]
    return cache["describe_images"]

@registry.register_check("ec2")
def ebs_volume_attachment_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.1] EBS Volumes should be in an attached state"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for volumes in describe_volumes(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volumes,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        volumeId = volumes["VolumeId"]
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        for attachments in volumes["Attachments"]:
            ebsAttachmentState = attachments["State"]
            # this is a failing check
            if ebsAttachmentState != "attached":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{volumeArn}/ebs-volume-attachment-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": volumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EBS.1] EBS Volumes should be in an attached state",
                    "Description": f"EBS Volume {volumeId} is not in an attached state. While detaching an EBS Volume is considered normal in certain aspects such as detaching extra mounted block storage or needing to preserve a boot volume from a deleted instance, you are still responsible for storage charges. Additionally, unattached volumes with sensitive data on are harder to safeguard and monitor the actual data on the volume. If you do not have a requirement to store detached volumes consider deleting them. Additionally, consider taking a Snapshot instead and deleting the Volume. With the Snapshot you can place additional IAM protections to ensure only certain principals can interact with the Snapshot and also prevent it from being shared. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon Elastic Block Storage",
                        "AssetComponent": "Volume"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": volumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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
                    "RecordState": "ACTIVE",
                }
                yield finding
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{volumeArn}/ebs-volume-attachment-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": volumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EBS.1] EBS Volumes should be in an attached state",
                    "Description": f"EBS Volume {volumeId} is in an attached state.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be attached refer to the Attaching an Amazon EBS Volume to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon Elastic Block Storage",
                        "AssetComponent": "Volume"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": volumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
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
def ebs_volume_delete_on_termination_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.2] EBS Volumes should be configured to be deleted on termination"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for volumes in describe_volumes(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volumes,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        volumeId = volumes["VolumeId"]
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        ebsAttachments = volumes["Attachments"]
        for attachments in ebsAttachments:
            ebsDeleteOnTerminationCheck = str(attachments["DeleteOnTermination"])
            # this is a failing check
            if ebsDeleteOnTerminationCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{volumeArn}/ebs-volume-delete-on-termination-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": volumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[EBS.2] EBS Volumes should be configured to be deleted on termination",
                    "Description": f"EBS Volume {volumeId} is not configured to be deleted on termination. By default, the DeleteOnTermination attribute for the root volume of an instance is set to true. Therefore, the default is to delete the root volume of the instance when the instance terminates. The DeleteOnTermination attribute can be set by the creator of an AMI as well as by the person who launches an instance. When the attribute is changed by the creator of an AMI or by the person who launches an instance, the new setting overrides the original AMI default setting. We recommend that you verify the default setting for the DeleteOnTermination attribute after you launch an instance with an AMI. By default, when you attach a non-root EBS volume to an instance, its DeleteOnTermination attribute is set to false. Therefore, the default is to preserve these volumes. After the instance terminates, you can take a snapshot of the preserved volume or attach it to another instance. You must delete a volume to avoid incurring further charges. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be deleted on instance termination refer to the Preserving Amazon EBS Volumes on Instance Termination section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#preserving-volumes-on-termination",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon Elastic Block Storage",
                        "AssetComponent": "Volume"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": volumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-3",
                            "NIST SP 800-53 Rev. 4 CM-8",
                            "NIST SP 800-53 Rev. 4 MP-6",
                            "NIST SP 800-53 Rev. 4 PE-16",
                            "AICPA TSC CC6.1",
                            "AICPA TSC CC6.5",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.8.3.1",
                            "ISO 27001:2013 A.8.3.2",
                            "ISO 27001:2013 A.8.3.3",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.7"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{volumeArn}/ebs-volume-delete-on-termination-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": volumeArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[EBS.2] EBS Volumes should be configured to be deleted on termination",
                    "Description": f"EBS Volume {volumeId} is configured to be deleted on termination.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your EBS volume should be deleted on instance termination refer to the Preserving Amazon EBS Volumes on Instance Termination section of the Amazon Elastic Compute Cloud User Guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/terminating-instances.html#preserving-volumes-on-termination",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon Elastic Block Storage",
                        "AssetComponent": "Volume"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Volume",
                            "Id": volumeArn,
                            "Partition": awsPartition,
                            "Region": awsRegion
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-3",
                            "NIST SP 800-53 Rev. 4 CM-8",
                            "NIST SP 800-53 Rev. 4 MP-6",
                            "NIST SP 800-53 Rev. 4 PE-16",
                            "AICPA TSC CC6.1",
                            "AICPA TSC CC6.5",
                            "ISO 27001:2013 A.8.2.3",
                            "ISO 27001:2013 A.8.3.1",
                            "ISO 27001:2013 A.8.3.2",
                            "ISO 27001:2013 A.8.3.3",
                            "ISO 27001:2013 A.11.2.5",
                            "ISO 27001:2013 A.11.2.7"
                    ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding

@registry.register_check("ec2")
def ebs_volume_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.3] EBS Volumes should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for volumes in describe_volumes(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volumes,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        volumeId = volumes["VolumeId"]
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        ebsEncryptionCheck = volumes["Encrypted"]
        # this is a failing check
        if ebsEncryptionCheck == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{volumeArn}/ebs-volume-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": volumeArn,
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
                "Title": "[EBS.3] EBS Volumes should be encrypted",
                "Description": f"EBS Volume {volumeId} is not encrypted. Use Amazon EBS encryption as a straight-forward encryption solution for your EBS resources associated with your EC2 instances. With Amazon EBS encryption, you aren't required to build, maintain, and secure your own key management infrastructure. Amazon EBS encryption uses AWS KMS keys when creating encrypted volumes and snapshots. Encryption operations occur on the servers that host EC2 instances, ensuring the security of both data-at-rest and data-in-transit between an instance and its attached EBS storage. Amazon EBS encrypts your volume with a data key using industry-standard AES-256 data encryption. The data key is generated by AWS KMS and then encrypted by AWS KMS with your AWS KMS key prior to being stored with your volume information. All snapshots, and any subsequent volumes created from those snapshots using the same AWS KMS key share the same data key. While EBS encryption will protect the in-transit traffic between the instance and the paravirtualized block storage attachment as well as the data written to disk, it will not protect the data in-use, nor will it appear encrypted to the actual file system on the operating system for your EC2 instances (or other services using EBS as block storage). Consider using your own encryption such as LUKS or Windows Encryption. Additionally, when using the default aws/ebs KMS key, this is tied to your Account and Region - if you intend to share snapshots, volumes or AMIs between Accounts and Regions consider using a KMS CMK instead. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS volume should be encrypted refer to the Amazon EBS Encryption section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "Encrypted": False
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{volumeArn}/ebs-volume-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": volumeArn,
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
                "Title": "[EBS.3] EBS Volumes should be encrypted",
                "Description": f"EBS Volume {volumeId} is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS volume should be encrypted refer to the Amazon EBS Encryption section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "Encrypted": True
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ebs_snapshot_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.4] EBS Snapshots should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for snapshots in describe_snapshots(cache, session, awsAccountId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(snapshots,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        snapshotId = snapshots["SnapshotId"]
        snapshotArn = f"arn:{awsPartition}:ec2:{awsRegion}::snapshot/{snapshotId}"
        # this is a failing check
        if snapshots["Encrypted"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snapshotArn}/ebs-snapshot-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snapshotArn,
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
                "Title": "[EBS.4] EBS Snapshots should be encrypted",
                "Description": f"EBS Snapshot {snapshotId} is not encrypted. Use Amazon EBS encryption as a straight-forward encryption solution for your EBS resources associated with your EC2 instances. With Amazon EBS encryption, you aren't required to build, maintain, and secure your own key management infrastructure. Amazon EBS encryption uses AWS KMS keys when creating encrypted volumes and snapshots. Encryption operations occur on the servers that host EC2 instances, ensuring the security of both data-at-rest and data-in-transit between an instance and its attached EBS storage. Amazon EBS encrypts your volume with a data key using industry-standard AES-256 data encryption. The data key is generated by AWS KMS and then encrypted by AWS KMS with your AWS KMS key prior to being stored with your volume information. All snapshots, and any subsequent volumes created from those snapshots using the same AWS KMS key share the same data key. While EBS encryption will protect the in-transit traffic between the instance and the paravirtualized block storage attachment as well as the data written to disk, it will not protect the data in-use, nor will it appear encrypted to the actual file system on the operating system for your EC2 instances (or other services using EBS as block storage). Consider using your own encryption such as LUKS or Windows Encryption. Additionally, when using the default aws/ebs KMS key, this is tied to your Account and Region - if you intend to share snapshots, volumes or AMIs between Accounts and Regions consider using a KMS CMK instead. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS snapshot should be encrypted refer to the Encryption Support for Snapshots section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/EBSSnapshots.html#encryption-support",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Snapshot"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Snapshot",
                        "Id": snapshotArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "Encrypted": False,
                                "SnapshotId": snapshotId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snapshotArn}/ebs-snapshot-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snapshotArn,
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
                "Title": "[EBS.4] EBS Snapshots should be encrypted",
                "Description": f"EBS Snapshot {snapshotId} is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS snapshot should be encrypted refer to the Encryption Support for Snapshots section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/EBSSnapshots.html#encryption-support",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Snapshot"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Snapshot",
                        "Id": snapshotArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "Encrypted": True,
                                "SnapshotId": snapshotId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-1",
                        "NIST SP 800-53 Rev. 4 MP-8",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "NIST SP 800-53 Rev. 4 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("ec2")
def ebs_snapshot_public_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.5] EBS Snapshots should not be public"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for snapshots in describe_snapshots(cache, session, awsAccountId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(snapshots,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        snapshotId = snapshots["SnapshotId"]
        snapshotArn = f"arn:{awsPartition}:ec2:{awsRegion}::snapshot/{snapshotId}"
        # determine if there are any permissions to share the snapshot
        r = ec2.describe_snapshot_attribute(
            Attribute="createVolumePermission",
            SnapshotId=snapshotId,
            DryRun=False
        )
        # this is a passing check
        if not r["CreateVolumePermissions"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{snapshotArn}/ebs-snapshot-public-share-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": snapshotArn,
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
                "Title": "[EBS.5] EBS Snapshots should not be public",
                "Description": f"EBS Snapshot {snapshotId} is private.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Snapshot"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Snapshot",
                        "Id": snapshotArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "SnapshotId": snapshotId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            for permissions in r["CreateVolumePermissions"]:
                # {'Group': 'all'} denotes public
                # you should still audit accounts you have shared
                # this is a failing check
                if str(permissions) == "{'Group': 'all'}":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{snapshotArn}/ebs-snapshot-public-share-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": snapshotArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[EBS.5] EBS Snapshots should not be public",
                        "Description": f"EBS Snapshot {snapshotId} is public. Snapshots that are public are restorable into Volumes or Amazon Machine Images (AMIs) by anyone with an AWS Account, if sensitive data is contained on the snapshot then adversaries can easily harvest it. Ensure you carefully examine the data stored onto root volumes as well as their permissions. There are some cases where it is perfectly viable to have a public snapshot, always seek to understand the business or mission context before unilaterally removing publicly-shared permissions from a Snapshot. Refer to the remediation instructions to remediate this behavior.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Storage",
                            "AssetService": "Amazon Elastic Block Storage",
                            "AssetComponent": "Snapshot"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Snapshot",
                                "Id": snapshotArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Volume": {
                                        "SnapshotId": snapshotId
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST CSF V1.1 PR.DS-5",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-4",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-14",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 AC-24",
                                "NIST SP 800-53 Rev. 4 PE-19",
                                "NIST SP 800-53 Rev. 4 PS-3",
                                "NIST SP 800-53 Rev. 4 PS-6",
                                "NIST SP 800-53 Rev. 4 SC-7",
                                "NIST SP 800-53 Rev. 4 SC-8",
                                "NIST SP 800-53 Rev. 4 SC-13",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "NIST SP 800-53 Rev. 4 SC-31",
                                "NIST SP 800-53 Rev. 4 SI-4",
                                "AICPA TSC CC6.3",
                                "AICPA TSC CC6.6",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.7.1.1",
                                "ISO 27001:2013 A.7.1.2",
                                "ISO 27001:2013 A.7.3.1",
                                "ISO 27001:2013 A.8.2.2",
                                "ISO 27001:2013 A.8.2.3",
                                "ISO 27001:2013 A.9.1.1",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "ISO 27001:2013 A.9.4.5",
                                "ISO 27001:2013 A.10.1.1",
                                "ISO 27001:2013 A.11.1.4",
                                "ISO 27001:2013 A.11.1.5",
                                "ISO 27001:2013 A.11.2.1",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.1.3",
                                "ISO 27001:2013 A.13.2.1",
                                "ISO 27001:2013 A.13.2.3",
                                "ISO 27001:2013 A.13.2.4",
                                "ISO 27001:2013 A.14.1.2",
                                "ISO 27001:2013 A.14.1.3"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    # this is an active check, but not failing
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{snapshotArn}/ebs-snapshot-public-share-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": snapshotArn,
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
                        "Title": "[EBS.5] EBS Snapshots should not be public",
                        "Description": f"EBS Snapshot {snapshotId} is private, however, this snapshot has been identified as being shared with other accounts. You should audit these accounts to ensure they are still authorized to have this snapshot shared with them.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your EBS snapshot should not be public refer to the Sharing an Amazon EBS Snapshot section of the Amazon Elastic Compute Cloud User Guide",
                                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ebs-modifying-snapshot-permissions.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Storage",
                            "AssetService": "Amazon Elastic Block Storage",
                            "AssetComponent": "Snapshot"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Snapshot",
                                "Id": snapshotArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Volume": {
                                        "SnapshotId": snapshotId
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST CSF V1.1 PR.AC-4",
                                "NIST CSF V1.1 PR.DS-5",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-2",
                                "NIST SP 800-53 Rev. 4 AC-3",
                                "NIST SP 800-53 Rev. 4 AC-4",
                                "NIST SP 800-53 Rev. 4 AC-5",
                                "NIST SP 800-53 Rev. 4 AC-6",
                                "NIST SP 800-53 Rev. 4 AC-14",
                                "NIST SP 800-53 Rev. 4 AC-16",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 AC-24",
                                "NIST SP 800-53 Rev. 4 PE-19",
                                "NIST SP 800-53 Rev. 4 PS-3",
                                "NIST SP 800-53 Rev. 4 PS-6",
                                "NIST SP 800-53 Rev. 4 SC-7",
                                "NIST SP 800-53 Rev. 4 SC-8",
                                "NIST SP 800-53 Rev. 4 SC-13",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "NIST SP 800-53 Rev. 4 SC-31",
                                "NIST SP 800-53 Rev. 4 SI-4",
                                "AICPA TSC CC6.3",
                                "AICPA TSC CC6.6",
                                "AICPA TSC CC7.2",
                                "ISO 27001:2013 A.6.1.2",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.7.1.1",
                                "ISO 27001:2013 A.7.1.2",
                                "ISO 27001:2013 A.7.3.1",
                                "ISO 27001:2013 A.8.2.2",
                                "ISO 27001:2013 A.8.2.3",
                                "ISO 27001:2013 A.9.1.1",
                                "ISO 27001:2013 A.9.1.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.4.1",
                                "ISO 27001:2013 A.9.4.4",
                                "ISO 27001:2013 A.9.4.5",
                                "ISO 27001:2013 A.10.1.1",
                                "ISO 27001:2013 A.11.1.4",
                                "ISO 27001:2013 A.11.1.5",
                                "ISO 27001:2013 A.11.2.1",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.1.3",
                                "ISO 27001:2013 A.13.2.1",
                                "ISO 27001:2013 A.13.2.3",
                                "ISO 27001:2013 A.13.2.4",
                                "ISO 27001:2013 A.14.1.2",
                                "ISO 27001:2013 A.14.1.3"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                # break the loop since we already evaluated
                break

@registry.register_check("ec2")
def ebs_account_encryption_by_default_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.6] Account-level EBS Volume encryption should be enabled"""
    ec2 = session.client("ec2")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # this is a failing check
    encrDetails = ec2.get_ebs_encryption_by_default(DryRun=False)
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(encrDetails,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if encrDetails["EbsEncryptionByDefault"] == False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}{awsRegion}/ebs-account-encryption-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[EBS.6] Account-level EBS Volume encryption should be enabled",
            "Description": f"Account-level EBS volume encryption is not enabled for AWS Account {awsAccountId} in {awsRegion}. You can configure your AWS account to enforce the encryption of the new EBS volumes and snapshot copies that you create. For example, Amazon EBS encrypts the EBS volumes created when you launch an instance and the snapshots that you copy from an unencrypted snapshot. Encryption by default is a Region-specific setting. If you enable it for a Region, you cannot disable it for individual volumes or snapshots in that Region. Amazon EBS encryption by default is supported on all current generation and previous generation instance types. If you copy a snapshot and encrypt it to a new KMS key, a complete (non-incremental) copy is created. This results in additional storage costs. When migrating servers using AWS Server Migration Service (SMS), do not turn on encryption by default. If encryption by default is already on and you are experiencing delta replication failures, turn off encryption by default. Instead, enable AMI encryption when you create the replication job. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on Account-level encryption refer to the Encryption by Default to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Amazon Elastic Block Storage",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EBS_Account_Level_Encryption_Setting",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.DS-1",
                    "NIST SP 800-53 Rev. 4 MP-8",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "NIST SP 800-53 Rev. 4 SC-28",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1",
                    "CIS Amazon Web Services Foundations Benchmark V2.0 2.2.1",
                    "CIS Amazon Web Services Foundations Benchmark V3.0 2.2.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    # this is a passing check
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}{awsRegion}/ebs-account-encryption-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}{awsRegion}",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[EBS.6] Account-level EBS Volume encryption should be enabled",
            "Description": f"Account-level EBS volume encryption is enabled for AWS Account {awsAccountId} in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on Account-level encryption refer to the Encryption by Default to an Instance section of the Amazon Elastic Compute Cloud User Guide",
                    "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Amazon Elastic Block Storage",
                "AssetComponent": "Account Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/{awsRegion}/EBS_Account_Level_Encryption_Setting",
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.DS-1",
                    "NIST SP 800-53 Rev. 4 MP-8",
                    "NIST SP 800-53 Rev. 4 SC-12",
                    "NIST SP 800-53 Rev. 4 SC-28",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.2.3",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1",
                    "CIS Amazon Web Services Foundations Benchmark V2.0 2.2.1",
                    "CIS Amazon Web Services Foundations Benchmark V3.0 2.2.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("ec2")
def ebs_volume_snapshot_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.7] EBS Volumes should have snapshots"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    for volumes in describe_volumes(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(volumes,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        volumeId = volumes["VolumeId"]
        volumeArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:volume/{volumeId}"
        # Check if there is a volume
        try:
            snapshotId = str(volumes["SnapshotId"])
        except KeyError:
            snapshotId = None
        # This is a passing finding        
        if snapshotId is not None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{volumeArn}/ebs-volume-snapshot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{volumeArn}/{snapshotId}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EBS.7] EBS Volumes should have snapshots",
                "Description": f"EBS Volume {volumeId} has a snapshot which can promote cyber resilience due to a viable backup.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS volume should be backed up via Snapshots refer to the Amazon EBS snapshots section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "SnapshotId": snapshotId
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{volumeArn}/ebs-volume-snapshot-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{volumeArn}/{snapshotId}",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[EBS.7] EBS Volumes should have snapshots",
                "Description": f"EBS Volume {volumeId} does not have a snapshot which can reduce cyber resilience due to a lack of a viable backup. You can back up the data on your Amazon EBS volumes to Amazon S3 by taking point-in-time snapshots. Snapshots are incremental backups, which means that only the blocks on the device that have changed after your most recent snapshot are saved. This minimizes the time required to create the snapshot and saves on storage costs by not duplicating data. AWS does not automatically back up data stored on your Amazon EBS volumes. For data resiliency and disaster recovery, it remains your responsibility to create regular backups using Amazon EBS snapshots, or to set up automatic snapshot creation using Amazon Data Lifecycle Manager or AWS Backup. Each snapshot contains all of the information that is needed to restore your data (from the moment when the snapshot was taken) to a new EBS volume. When you create an EBS volume based on a snapshot, the new volume begins as an exact replica of the original volume that was used to create the snapshot. The replicated volume loads data in the background so that you can begin using it immediately. If you access data that hasn't been loaded yet, the volume immediately downloads the requested data from Amazon S3, and then continues loading the rest of the volume's data in the background. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your EBS volume should be backed up via Snapshots refer to the Amazon EBS snapshots section of the Amazon Elastic Compute Cloud User Guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon Elastic Block Storage",
                    "AssetComponent": "Volume"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Volume",
                        "Id": volumeArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsEc2Volume": {
                                "SnapshotId": snapshotId
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

@registry.register_check("ec2")
def public_ami_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.8] Self-managed Amazon Machine Images (AMIs) should not be publicly available"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ami in describe_images(cache, session, awsAccountId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ami,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        imageId = ami["ImageId"]
        amiArn = f"arn:{awsPartition}:ec2:{awsRegion}::image/{imageId}"
        imageName = ami["Name"]
        imageCreatedDate = str(ami["CreationDate"])        
        if ami["Public"] == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{amiArn}/public-ami",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": amiArn,
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
                "Title": "[EBS.8] Self-managed Amazon Machine Images (AMIs) should not be publicly available",
                "Description": "Amazon Machine Image (AMI) "
                + imageName
                + " is exposed to the public. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Image"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Image",
                        "Id": amiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ImageId": imageId, 
                                "ImageCreatedDate": imageCreatedDate
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{amiArn}/public-ami",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": amiArn,
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
                "Title": "[EBS.8] Self-managed Amazon Machine Images (AMIs) should not be publicly available",
                "Description": "Amazon Machine Image (AMI) " + imageName + " is private.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Amazon EC2",
                    "AssetComponent": "Image"
                },
                "Resources": [
                    {
                        "Type": "AwsEc2Image",
                        "Id": amiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ImageId": imageId, 
                                "ImageCreatedDate": imageCreatedDate
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("ec2")
def encrypted_ami_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EBS.9] Self-managed Amazon Machine Images (AMIs) should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ami in describe_images(cache, session, awsAccountId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ami,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        imageId = ami["ImageId"]
        amiArn = f"arn:{awsPartition}:ec2:{awsRegion}::image/{imageId}"
        imageName = ami["Name"]
        imageCreatedDate = str(ami["CreationDate"])
        for ebsmapping in ami["BlockDeviceMappings"]:
            try:
                encryptionCheck = ebsmapping["Ebs"]["Encrypted"]
            except KeyError:
                encryptionCheck = False
            if encryptionCheck is False:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{amiArn}/encrypted-ami",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": amiArn,
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
                    "Title": "[EBS.9] Self-managed Amazon Machine Images (AMIs) should be encrypted",
                    "Description": f"Amazon Machine Image (AMI) {imageName} is not encrypted. AMIs that are backed by Amazon EBS snapshots can take advantage of Amazon EBS encryption. Snapshots of both data and root volumes can be encrypted and attached to an AMI. You can launch instances and copy images with full EBS encryption support included. Encryption parameters for these operations are supported in all Regions where AWS KMS is available. EC2 instances with encrypted EBS volumes are launched from AMIs in the same way as other instances. In addition, when you launch an instance from an AMI backed by unencrypted EBS snapshots, you can encrypt some or all of the volumes during launch. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Image"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Image",
                            "Id": amiArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ImageId": imageId, 
                                    "ImageCreatedDate": imageCreatedDate
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{amiArn}/encrypted-ami",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": amiArn,
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
                    "Title": "[EBS.9] Self-managed Amazon Machine Images (AMIs) should be encrypted",
                    "Description": "Amazon Machine Image (AMI) " + imageName + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Storage",
                        "AssetService": "Amazon EC2",
                        "AssetComponent": "Image"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEc2Image",
                            "Id": amiArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "ImageId": imageId, 
                                    "ImageCreatedDate": imageCreatedDate
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.DS-1",
                            "NIST SP 800-53 Rev. 4 MP-8",
                            "NIST SP 800-53 Rev. 4 SC-12",
                            "NIST SP 800-53 Rev. 4 SC-28",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.8.2.3",
                            "CIS Amazon Web Services Foundations Benchmark V1.5 2.2.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

## EOF?