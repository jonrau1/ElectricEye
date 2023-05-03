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

def list_buckets(cache, session):
    s3 = session.client("s3")
    response = cache.get("list_buckets")
    if response:
        return response
    cache["list_buckets"] = s3.list_buckets()
    return cache["list_buckets"]

@registry.register_check("s3")
def bucket_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.1] S3 Buckets should be encrypted"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    iso8601Time = (
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        try:
            response = s3.get_bucket_encryption(Bucket=bucketName)
            for rules in response["ServerSideEncryptionConfiguration"]["Rules"]:
                sseType = str(
                    rules["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                )
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
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
                    "Title": "[S3.1] S3 Buckets should be encrypted",
                    "Description": "S3 bucket "
                    + bucketName
                    + " is encrypted using "
                    + sseType
                    + ".",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
        except Exception as e:
            if (
                str(e)
                == "An error occurred (ServerSideEncryptionConfigurationNotFoundError) when calling the GetBucketEncryption operation: The server side encryption configuration was not found"
            ):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
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
                    "Title": "[S3.1] S3 Buckets should be encrypted",
                    "Description": "S3 bucket "
                    + bucketName
                    + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                print(e)

@registry.register_check("s3")
def bucket_lifecycle_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucketName)
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": s3Arn + "/s3-bucket-lifecyle-configuration-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": s3Arn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations",
                "Description": "S3 bucket "
                + bucketName
                + " has a lifecycle policy configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Lifecycle policies and how to configure it refer to the How Do I Create a Lifecycle Policy for an S3 Bucket? section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-lifecycle.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": s3Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except Exception as e:
            if (
                str(e)
                == "An error occurred (NoSuchLifecycleConfiguration) when calling the GetBucketLifecycleConfiguration operation: The lifecycle configuration does not exist"
            ):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-lifecyle-configuration-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[S3.2] S3 Buckets should implement lifecycle policies for data archival and recovery operations",
                    "Description": "S3 bucket "
                    + bucketName
                    + " does not have a lifecycle policy configured. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Lifecycle policies and how to configure it refer to the How Do I Create a Lifecycle Policy for an S3 Bucket? section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-lifecycle.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.BE-5",
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 SA-13",
                            "NIST SP 800-53 Rev. 4 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(e)

@registry.register_check("s3")
def bucket_versioning_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.3] S3 Buckets should have versioning enabled"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        try:
            response = s3.get_bucket_versioning(Bucket=bucketName)
            versioningCheck = str(response["Status"])
            print(versioningCheck)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": s3Arn + "/s3-bucket-versioning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": s3Arn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.3] S3 Buckets should have versioning enabled",
                "Description": "S3 bucket "
                + bucketName
                + " has versioning enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Versioning and how to configure it refer to the Using Versioning section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": s3Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 SA-13",
                        "NIST SP 800-53 Rev. 4 SA14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except Exception as e:
            if str(e) == "'Status'":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-versioning-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[S3.3] S3 Buckets should have versioning enabled",
                    "Description": "S3 bucket "
                    + bucketName
                    + " does not have versioning enabled. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Versioning and how to configure it refer to the Using Versioning section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.BE-5",
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 SA-13",
                            "NIST SP 800-53 Rev. 4 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(e)

@registry.register_check("s3")
def bucket_policy_allows_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.4] S3 Bucket Policies should not allow public access to the bucket"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        try:
            response = s3.get_bucket_policy(Bucket=bucketName)
            try:
                response = s3.get_bucket_policy_status(Bucket=bucketName)
                publicBucketPolicyCheck = str(response["PolicyStatus"]["IsPublic"])
                if publicBucketPolicyCheck != "False":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": s3Arn + "/s3-bucket-policy-allows-public-access-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": s3Arn,
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
                        "Title": "[S3.4] S3 Bucket Policies should not allow public access to the bucket",
                        "Description": "S3 bucket "
                        + bucketName
                        + " has a bucket policy attached that allows public access. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html",
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
                            "AssetService": "Amazon S3",
                            "AssetComponent": "Bucket"
                        },
                        "Resources": [
                            {
                                "Type": "AwsS3Bucket",
                                "Id": s3Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
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
                        "Id": s3Arn + "/s3-bucket-policy-allows-public-access-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": s3Arn,
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
                        "Title": "[S3.4] S3 Bucket Policies should not allow public access to the bucket",
                        "Description": "S3 bucket "
                        + bucketName
                        + " has a bucket policy attached and it does not allow public access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                                "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html",
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
                            "AssetService": "Amazon S3",
                            "AssetComponent": "Bucket"
                        },
                        "Resources": [
                            {
                                "Type": "AwsS3Bucket",
                                "Id": s3Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
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
            except Exception as e:
                print(e)
        except Exception as e:
            # This bucket does not have a bucket policy and the status cannot be checked
            pass

@registry.register_check("s3")
def bucket_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.5] S3 Buckets should have a bucket policy configured"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        try:
            s3.get_bucket_policy(Bucket=bucketName)
            # print("This bucket has a policy but we wont be printing that in the logs lol")
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": s3Arn + "/s3-bucket-policy-exists-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": s3Arn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.5] S3 Buckets should have a bucket policy configured",
                "Description": "S3 bucket "
                + bucketName
                + " has a bucket policy configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": s3Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
        except Exception as e:
            if (
                str(e)
                == "An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist"
            ):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-policy-exists-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[S3.5] S3 Buckets should have a bucket policy configured",
                    "Description": "S3 bucket "
                    + bucketName
                    + " does not have a bucket policy configured. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                print(e)

@registry.register_check("s3")
def bucket_access_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.6] S3 Buckets should have server access logging enabled"""
    s3 = session.client("s3")
    bucket = list_buckets(cache, session)
    myS3Buckets = bucket["Buckets"]
    for buckets in myS3Buckets:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = str(buckets["Name"])
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        iso8601Time = (
            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        )
        try:
            s3.get_bucket_logging(Bucket=bucketName)["LoggingEnabled"]
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": s3Arn + "/s3-bucket-server-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": s3Arn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.6] S3 Buckets should have server access logging enabled",
                "Description": "S3 bucket "
                + bucketName
                + " does not have server access logging enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Amazon S3 Server Access Logging section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": s3Arn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except Exception as e:
            if str(e) == "'LoggingEnabled'":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": s3Arn + "/s3-bucket-server-access-logging-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": s3Arn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[S3.6] S3 Buckets should have server access logging enabled",
                    "Description": "S3 bucket "
                    + bucketName
                    + " does not have server access logging enabled. Refer to the remediation instructions to remediate this behavior",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Policies and how to configure it refer to the Amazon S3 Server Access Logging section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
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
                        "AssetService": "Amazon S3",
                        "AssetComponent": "Bucket"
                    },
                    "Resources": [
                        {
                            "Type": "AwsS3Bucket",
                            "Id": s3Arn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                print(e)

@registry.register_check("s3")
def s3_account_level_block(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.7] Account-level S3 public access block should be configured"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    s3control = session.client("s3control")

    # If a Public Access Block is not configured at all we will fail with a higher severity
    try:
        response = s3control.get_public_access_block(AccountId=awsAccountId)
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(response,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        accountBlock = response["PublicAccessBlockConfiguration"]
        blockAcl = str(accountBlock["BlockPublicAcls"])
        ignoreAcl = str(accountBlock["IgnorePublicAcls"])
        blockPubPolicy = str(accountBlock["BlockPublicPolicy"])
        restrictPubBuckets = str(accountBlock["RestrictPublicBuckets"])

        if (
            blockAcl 
            and ignoreAcl
            and blockPubPolicy 
            and restrictPubBuckets == "True"
        ):
        # This is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/s3-account-level-public-access-block-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId,
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
                "Title": "[S3.7] Account-level S3 public access block should be configured",
                "Description": "Account-level S3 public access block for account "
                + awsAccountId
                + " is enabled",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Account Configuration"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/S3_Block_Public_Access_Configuration",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
        else:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/s3-account-level-public-access-block-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[S3.7] Account-level S3 public access block should be configured",
                "Description": "Account-level S3 public access block for account "
                + awsAccountId
                + " is either inactive or is not block all possible scenarios. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Account Configuration"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/S3_Block_Public_Access_Configuration",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
    except Exception as e:
        if str(e) == "An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found":
            assetB64 = None
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": awsAccountId + "/s3-account-level-public-access-block-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId,
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
                "Title": "[S3.7] Account-level S3 public access block should be configured",
                "Description": f"Account-level S3 public access block for account {awsAccountId} is not configured. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
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
                    "AssetService": "Amazon S3",
                    "AssetComponent": "Account Configuration"
                },
                "Resources": [
                    {
                        "Type": "AwsAccount",
                        "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/S3_Block_Public_Access_Configuration",
                        "Partition": awsPartition,
                        "Region": awsRegion,
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            pass