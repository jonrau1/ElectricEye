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
from botocore.exceptions import ClientError

registry = CheckRegister()

def global_region_generator(awsPartition):
    # Global Service Region override
    if awsPartition == "aws":
        globalRegion = "aws-global"
    elif awsPartition == "aws-us-gov":
        globalRegion = "aws-us-gov-global"
    elif awsPartition == "aws-cn":
        globalRegion = "aws-cn-global"
    elif awsPartition == "aws-iso":
        globalRegion = "aws-iso-global"
    elif awsPartition == "aws-isob":
        globalRegion = "aws-iso-b-global"
    elif awsPartition == "aws-isoe":
        globalRegion = "aws-iso-e-global"
    else:
        globalRegion = "aws-global"

    return globalRegion

def list_buckets(cache, session):
    response = cache.get("list_buckets")
    if response:
        return response
    
    s3 = session.client("s3")

    cache["list_buckets"] = s3.list_buckets()["Buckets"]
    return cache["list_buckets"]

@registry.register_check("s3")
def aws_s3_bucket_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.1] AWS S3 Buckets should be encrypted"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
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
                    "Title": "[S3.1] AWS S3 Buckets should be encrypted",
                    "Description": "AWS S3 bucket "
                    + bucketName
                    + " is encrypted using "
                    + sseType
                    + ".",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
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
                            "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
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
                    "Title": "[S3.1] AWS S3 Buckets should be encrypted",
                    "Description": "AWS S3 bucket "
                    + bucketName
                    + " is not encrypted. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Bucket Encryption and how to configure it refer to the Amazon S3 Default Encryption for S3 Buckets section of the Amazon Simple Storage Service Developer Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": global_region_generator(awsPartition),
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
                            "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                print(e)

@registry.register_check("s3")
def aws_s3_bucket_lifecycle_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.2] AWS S3 Buckets should implement lifecycle policies for data archival and recovery operations"""
    s3 = session.client("s3")
    # ISO Time
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
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
                "Title": "[S3.2] AWS S3 Buckets should implement lifecycle policies for data archival and recovery operations",
                "Description": "AWS S3 bucket "
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
                    "AssetRegion": global_region_generator(awsPartition),
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
                    "Title": "[S3.2] AWS S3 Buckets should implement lifecycle policies for data archival and recovery operations",
                    "Description": f"AWS S3 bucket {bucketName} does not have a lifecycle policy configured. S3 Lifecycle Policies can help lower data management tasks, lower storage costs, and get rid of corrupted or incomplete objects within your buckets. You can configure S3 to move objects to lower cost storage such as Infrequent Access or you can send objects to long-term storage in Amazon Glacier. If you have regulatory or industry compliance requirements to store certain types of data or logs, lifecycle policies is an automatable and auditable way to accomplish that. Likewise, if you have requirements to delete data after a certain amount of time a lifecycle policy can also accomodate that requirement. Refer to the remediation instructions if this configuration is not intended.",
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
                        "AssetRegion": global_region_generator(awsPartition),
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
            else:
                print(e)

@registry.register_check("s3")
def aws_s3_bucket_versioning_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.3] AWS S3 Buckets should have versioning enabled"""
    s3 = session.client("s3")
    # ISO Time
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
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
                "Title": "[S3.3] AWS S3 Buckets should have versioning enabled",
                "Description": "AWS S3 bucket "
                + bucketName
                + " has versioning enabled. Refer to the remediation instructions if this configuration is not intended.",
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
                    "AssetRegion": global_region_generator(awsPartition),
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
                "RecordState": "ARCHIVED",
            }
            yield finding
        except KeyError:
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
                "Title": "[S3.3] AWS S3 Buckets should have versioning enabled",
                "Description": "AWS S3 bucket "
                + bucketName
                + " does not have versioning enabled. Refer to the remediation instructions if this configuration is not intended.",
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
                    "AssetRegion": global_region_generator(awsPartition),
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
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("s3")
def aws_s3_bucket_policy_allows_public_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.4] AWS S3 Bucket Policies should not allow public access to the bucket"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        # A bucket (for the most part) requires explicit settings in a Bucket Polocy to make it Public
        # if there is not a Policy, or the Policy doesn't return "IsPublic" then it's not
        try:
            bucketPublic = s3.get_bucket_policy_status(Bucket=bucketName)["PolicyStatus"]["IsPublic"]
        except ClientError:
            bucketPublic = False

        # this is a failing check
        if bucketPublic is True:
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
                "Title": "[S3.4] AWS S3 Bucket Policies should not allow public access to the bucket",
                "Description": f"AWS S3 bucket {bucketName} has a bucket policy attached that allows public access. When a Bucket Policy is assessed as being public it means that unauthenticated and anonymous users can access the objects within the bucket and download them. While there are some business use cases such as serving up static assets or public datasets, you should still use Amazon CloudFront (or another Content Delivery Network solution) and other safeguards to prevent abuse. Several large data breaches have been from the result of having a public bucket, this is a high priority finding to investigate! Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Bucket Policy Examples section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                    ]
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
                "Title": "[S3.4] AWS S3 Bucket Policies should not allow public access to the bucket",
                "Description": "AWS S3 bucket "
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
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("s3")
def aws_s3_bucket_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.5] AWS S3 Buckets should have a bucket policy configured"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        # Check to see if there is a policy at all
        try:
            s3.get_bucket_policy(Bucket=bucketName)
            bucketHasPolicy = True
        except ClientError:
            bucketHasPolicy = False
        # this is a failing check
        if bucketHasPolicy is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-policy-exists-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-policy-exists-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[S3.5] AWS S3 Buckets should have a bucket policy configured",
                "Description": f"AWS S3 bucket {bucketName} does not have a bucket policy configured. A bucket policy is a resource-based policy that you can use to grant access permissions to your Amazon S3 bucket and the objects in it. Only the bucket owner can associate a policy with a bucket. The permissions attached to the bucket apply to all of the objects in the bucket that are owned by the bucket owner. These permissions do not apply to objects that are owned by other AWS accounts. S3 Object Ownership is an Amazon S3 bucket-level setting that you can use to control ownership of objects uploaded to your bucket and to disable or enable ACLs. By default, Object Ownership is set to the Bucket owner enforced setting and all ACLs are disabled. The bucket owner owns all the objects in the bucket and manages access to data exclusively using policies. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Using bucket policies section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "Region": awsRegion
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-policy-exists-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-policy-exists-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.5] AWS S3 Buckets should have a bucket policy configured",
                "Description": f"AWS S3 bucket {bucketName} does have a bucket policy configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Using bucket policies section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "Region": awsRegion
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("s3")
def aws_s3_bucket_access_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.6] AWS S3 Buckets should have server access logging enabled"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        # attempt to get server access logging
        try:
            s3.get_bucket_logging(Bucket=bucketName)["LoggingEnabled"]
            bucketServerLogging = True
        except ClientError:
            bucketServerLogging = False
        except KeyError:
            bucketServerLogging = False
        # this is a passing check
        if bucketServerLogging is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-server-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-server-access-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.6] AWS S3 Buckets should have server access logging enabled",
                "Description": f"AWS S3 bucket {bucketName} does have server access logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Bucket Policies and how to configure it refer to the Amazon S3 Server Access Logging section of the Amazon Simple Storage Service Developer Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-server-access-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-server-access-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[S3.6] AWS S3 Buckets should have server access logging enabled",
                "Description": f"AWS S3 bucket {bucketName} does not have server access logging enabled. Server access logging provides detailed records for the requests that are made to a bucket. Server access logs are useful for many applications. For example, access log information can be useful in security and access audits. It can also help you learn about your customer base and understand your Amazon S3 bill. Outside of managing static web applications from S3, consider using richer and more modern types of logs and other components such as pairing with Amazon CloudFront with Real-time logging. Refer to the remediation instructions if this configuration is not intended.",
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
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding

@registry.register_check("s3")
def s3_account_level_block(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.7] Account-level S3 public access block should be configured"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    s3control = session.client("s3control")
    # Make a fake ARN
    accountBlockArn = f"arn:{awsPartition}:s3::{awsAccountId}:account-public-access-block"
    # If a Public Access Block is not configured at all we will fail with a higher severity
    try:
        blocker = s3control.get_public_access_block(AccountId=awsAccountId)["PublicAccessBlockConfiguration"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(blocker,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # If they're all True it's good
        if (
            blocker["BlockPublicAcls"]
            and blocker["IgnorePublicAcls"]
            and blocker["BlockPublicPolicy"]
            and blocker["RestrictPublicBuckets"]
        ):
            accountPublicBlock = True
        else:
            accountPublicBlock = False
    except Exception:
        accountPublicBlock = False
        assetB64 = None

    # This is a passing check
    if accountPublicBlock is True:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{accountBlockArn}/s3-account-level-public-access-block-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{accountBlockArn}/s3-account-level-public-access-block-check",
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
                    "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Amazon S3",
                "AssetComponent": "Account Public Access Block Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": accountBlockArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{accountBlockArn}/s3-account-level-public-access-block-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{accountBlockArn}/s3-account-level-public-access-block-check",
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
            "Description": f"Account-level S3 public access block for account {awsAccountId} is either inactive or is not block all possible scenarios. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Account level S3 public access block and how to configure it refer to the Using Amazon S3 Block Public Access section of the Amazon Simple Storage Service Developer Guide",
                    "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": global_region_generator(awsPartition),
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Amazon S3",
                "AssetComponent": "Account Public Access Block Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": accountBlockArn,
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "ISO 27001:2013 A.14.1.3",
                    "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.5"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("s3")
def aws_s3_bucket_deny_http_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[S3.8] AWS S3 Buckets should define a policy block insecure (HTTP) access to all objects"""
    s3 = session.client("s3")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for buckets in list_buckets(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(buckets,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        bucketName = buckets["Name"]
        s3Arn = f"arn:{awsPartition}:s3:::{bucketName}"
        # Attempt to find a blocking policy for HTTP - default the status to not passing
        blockHttpObjectAccess = False
        try:
            bucketPolicy = s3.get_bucket_policy(Bucket=bucketName)["Policy"]
            for statement in bucketPolicy["Statement"]:
                if s3Arn and f"{s3Arn}/*" in statement["Resource"]:
                    if statement["Effect"] == "Deny" and statement["Action"] == "s3:*":
                        if "Condition" in statement:
                            if "Bool" in statement["Condition"]:
                                if statement["Condition"]["Bool"].get("aws:SecureTransport") == "false":
                                    blockHttpObjectAccess = True
                                    break
        except ClientError:
            blockHttpObjectAccess = False
        
        # This is a failing check
        if blockHttpObjectAccess is not True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-block-insecure-http-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-block-insecure-http-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[S3.8] AWS S3 Buckets should define a policy block insecure (HTTP) access to all objects",
                "Description": f"AWS S3 bucket {bucketName} does not define a policy to block insecure (HTTP) access to all objects. Amazon S3 offers encryption in transit and encryption at rest. Encryption in transit refers to HTTPS and encryption at rest refers to client-side or server-side encryption. Amazon S3 allows both HTTP and HTTPS requests. By default, requests are made through the AWS Management Console, AWS Command Line Interface (AWS CLI), or HTTPS. To prevent any insecure requests, confirm that your bucket policies explicitly deny access to objects without HTTPs by using. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on creating a compliant policy to block insecure (HTTP) access to all Objects refer to the What S3 bucket policy should I use to comply with the AWS Config rule s3-bucket-ssl-requests-only? Knowledge Center post in AWS re:Post",
                        "Url": "https://repost.aws/knowledge-center/s3-bucket-policy-for-config-rule"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{s3Arn}/s3-bucket-block-insecure-http-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{s3Arn}/s3-bucket-block-insecure-http-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[S3.8] AWS S3 Buckets should define a policy block insecure (HTTP) access to all objects",
                "Description": f"AWS S3 bucket {bucketName} does define a policy to block insecure (HTTP) access to all objects.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on creating a compliant policy to block insecure (HTTP) access to all Objects refer to the What S3 bucket policy should I use to comply with the AWS Config rule s3-bucket-ssl-requests-only? Knowledge Center post in AWS re:Post",
                        "Url": "https://repost.aws/knowledge-center/s3-bucket-policy-for-config-rule"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": global_region_generator(awsPartition),
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
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Amazon Web Services Foundations Benchmark V1.5 2.1.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## EOF ?