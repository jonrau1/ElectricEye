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

def describe_images(cache, session, awsAccountId):
    ec2 = session.client("ec2")
    response = cache.get("describe_images")
    if response:
        return response
    cache["describe_images"] = ec2.describe_images(
        Filters=[{"Name": "owner-id", "Values": [awsAccountId]}], DryRun=False
    )
    return cache["describe_images"]

@registry.register_check("ec2")
def public_ami_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AMI.1] Self-managed Amazon Machine Images (AMIs) should not be public"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ami in describe_images(cache, session, awsAccountId)["Images"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ami,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        imageId = str(ami["ImageId"])
        amiArn = f"arn:{awsPartition}:ec2:{awsRegion}::image/{imageId}"
        imageName = str(ami["Name"])
        imageCreatedDate = str(ami["CreationDate"])        
        if ami["Public"] == True:
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
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("ec2")
def encrypted_ami_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[AMI.2] Self-managed Amazon Machine Images (AMIs) should be encrypted"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for ami in describe_images(cache, session, awsAccountId)["Images"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(ami,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        imageId = str(ami["ImageId"])
        amiArn = f"arn:{awsPartition}:ec2:{awsRegion}::image/{imageId}"
        imageName = str(ami["Name"])
        imageCreatedDate = str(ami["CreationDate"])
        for ebsmapping in ami["BlockDeviceMappings"]:
            try:
                encryptionCheck = str(ebsmapping["Ebs"]["Encrypted"])
            except KeyError:
                continue
            if encryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": amiArn + "/encrypted-ami",
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": amiArn + "/encrypted-ami",
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
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding