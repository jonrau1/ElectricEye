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
ec2 = boto3.client("ec2")
# find AMIs created by the account
def describe_images(cache, awsAccountId):
    response = cache.get("describe_images")
    if response:
        return response
    cache["describe_images"] = ec2.describe_images(
        Filters=[{"Name": "owner-id", "Values": [awsAccountId]}], DryRun=False
    )
    return cache["describe_images"]


@registry.register_check("ami")
def public_ami_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    amis = describe_images(cache=cache, awsAccountId=awsAccountId)
    myAmis = amis["Images"]
    for ami in myAmis:
        imageId = str(ami["ImageId"])
        amiArn = "arn:aws:ec2:" + awsRegion + "::image/" + imageId
        imageName = str(ami["Name"])
        imageCreatedDate = str(ami["CreationDate"])
        publicCheck = str(ami["Public"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if publicCheck == "True":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": amiArn + "/public-ami",
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
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[AMI.1] Self-managed Amazon Machine Images (AMIs) should not be public",
                "Description": "Amazon Machine Image (AMI) "
                + imageName
                + " is exposed to the public. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": amiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"imageId": imageId, "imageCreatedDate": imageCreatedDate}
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
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": amiArn + "/public-ami",
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
                "Title": "[AMI.1] Self-managed Amazon Machine Images (AMIs) should not be public",
                "Description": "Amazon Machine Image (AMI) " + imageName + " is private.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your AMI is not intended to be public refer to the Sharing an AMI with Specific AWS Accounts section of the EC2 user guide",
                        "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-explicit.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "Other",
                        "Id": amiArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {"imageId": imageId, "imageCreatedDate": imageCreatedDate}
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
                    ],
                },
                "Workflow": {"Status": "REVOKED"},
                "RecordState": "ARCHIVED",
            }
            yield finding


@registry.register_check("ami")
def encrypted_ami_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    amis = describe_images(cache=cache, awsAccountId=awsAccountId)
    myAmis = amis["Images"]
    for ami in myAmis:
        imageId = str(ami["ImageId"])
        amiArn = "arn:aws:ec2:" + awsRegion + "::image/" + imageId
        imageName = str(ami["Name"])
        imageCreatedDate = str(ami["CreationDate"])
        BlockDevices = ami["BlockDeviceMappings"]
        for ebsmapping in BlockDevices:
            encryptionCheck = str(ebsmapping["Ebs"]["Encrypted"])
            iso8601Time = (
                datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
            )
            if encryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": amiArn + "/public-ami",
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
                    "Title": "[AMI.2] Self-managed Amazon Machine Images (AMIs) should be encrypted",
                    "Description": "Amazon Machine Image (AMI) "
                    + imageName
                    + " is not encrypted. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": amiArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"imageId": imageId, "imageCreatedDate": imageCreatedDate}
                            },
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
                    "Id": amiArn + "/public-ami",
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
                    "Title": "[AMI.2] Self-managed Amazon Machine Images (AMIs) should be encrypted",
                    "Description": "Amazon Machine Image (AMI) " + imageName + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your AMI should be encrypted refer to the Image-Copying Scenarios section of the EC2 user guide",
                            "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html#AMI-encryption-copy",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "Other",
                            "Id": amiArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {"imageId": imageId, "imageCreatedDate": imageCreatedDate}
                            },
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
