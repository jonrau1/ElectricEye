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

import os
import oci
from oci.config import validate_config
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def process_response(responseObject):
    """
    Receives an OCI Python SDK `Response` type (differs by service) and returns a JSON object
    """

    payload = json.loads(
        str(
            responseObject
        )
    )

    return payload

def get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_object_storage_buckets")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    objectStorageClient = oci.object_storage.ObjectStorageClient(config)

    aBigListOfBuckets = []

    for compartment in ociCompartments:
        # Each Oracle Cloud Infrastructure tenant is assigned one unique and uneditable Object Storage namespace.
        # The namespace is a system-generated string assigned during account creation.
        namespaceId = str(objectStorageClient.get_namespace(compartment_id=compartment).data)
        # Namespace is probably the same for every compartment...
        for bucket in objectStorageClient.list_buckets(namespace_name=namespaceId, compartment_id=compartment).data:
            bucket = process_response(bucket)
            bucketName = bucket["name"]
            # Only the GetBucket API has the extended information, not the ListBucket API
            bucketInfo = process_response(
                objectStorageClient.get_bucket(
                    namespace_name=namespaceId, bucket_name=bucketName
                ).data
            )
            # Get the Lifecycle Policies, if there are not any write any empty list
            try:
                lifeCycleInfo = process_response(
                    objectStorageClient.get_object_lifecycle_policy(
                        namespace_name=namespaceId, bucket_name=bucketName
                    ).data
                )["items"]
            except oci.exceptions.ServiceError:
                lifeCycleInfo = []
            # Insert the lifecycle into a new dict
            bucketInfo["object_lifecycle_policies"] = lifeCycleInfo
            # Append the new payload
            aBigListOfBuckets.append(bucketInfo)

    cache["get_object_storage_buckets"] = aBigListOfBuckets
    return cache["get_object_storage_buckets"]

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_cmk_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.1] Object Storage buckets should be encrypted with a Customer-managed Master Encryption Key
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        if bucket["kms_key_id"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.1] Object Storage buckets should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key. The Oracle Cloud Infrastructure Object Storage service encrypts and decrypts all objects using 256-bit Advanced Encryption Standard (AES-256) to encrypt object data on the server. Each object is encrypted with its own data encryption key. Data encryption keys are always encrypted with a master encryption key that is assigned to the bucket. Encryption is enabled by default and cannot be turned off. By default, Oracle manages the master encryption key. The Oracle Cloud Infrastructure Object Storage service encrypts your data and metadata (customer-provided key value pairs) using randomly generated Data Encryption Keys (DEKs). Object Storage allows you to specify your own Master Encryption Key (MEK) managed by the Vault service for buckets and individual objects. You can specify the MEK to be used for a given object without having to maintain and manage your own keys. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your buckets refer to the Using Your Own Keys in Vault for Server-Side Encryption section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/encryption.htm#UsingYourKMSKeys",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.1] Object Storage buckets should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your buckets refer to the Using Your Own Keys in Vault for Server-Side Encryption section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/encryption.htm#UsingYourKMSKeys",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_lifecycle_policy_defined_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.2] Object Storage buckets should have a lifecycle policy defined
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        if bucket["object_lifecycle_policy_etag"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-lifecycle-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.2] Object Storage buckets should have a lifecycle policy defined",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does not have a lifecycle policy defined. By using Object Lifecycle Management to manage your Object Storage and Archive Storage data, you can reduce your storage costs and the amount of time you spend manually managing data. Object Lifecycle Management works by taking automated action based on rules that you define. These rules instruct Object Storage to delete uncommitted multipart uploads, move objects to a different storage tier, and delete supported resources on your behalf within a given bucket. A bucket's lifecycle rules are collectively known as an object lifecycle policy. The resources that Object Lifecycle Management supports include objects, object versions, and uncommitted or failed multipart uploads. Each Object Storage or Archive Storage bucket can have a single lifecycle policy consisting of up to 1,000 rules. Object-related rules can have object name prefix and pattern matching conditions. Uncommitted multipart upload rules do not support prefix and pattern matching conditions. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a lifecycle policies for your buckets refer to the Using Object Lifecycle Management section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usinglifecyclepolicies.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
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
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-lifecycle-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.2] Object Storage buckets should have a lifecycle policy defined",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does have a lifecycle policy defined.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a lifecycle policies for your buckets refer to the Using Object Lifecycle Management section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usinglifecyclepolicies.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_multipart_delete_lifecycle_policy_defined_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.3] Object Storage buckets should define a lifecycle policy rule to delete failed multipart uploads
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        # Logic to check for a failed multi-part deletion policy. If there are not any lifecycle policies this automatically fails
        if not bucket["object_lifecycle_policies"]:
            multiPartRulePresent = False
        # Use any() to evaluate all of the rules within the list we created in the cache
        if any(rule["target"] == "multipart-uploads" and rule["is_enabled"] for rule in bucket["object_lifecycle_policies"]):
            multiPartRulePresent = True
        else:
            multiPartRulePresent = False

        if multiPartRulePresent is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-failed-multipart-delete-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-failed-multipart-delete-lifecycle-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.3] Object Storage buckets should define a lifecycle policy rule to delete failed multipart uploads",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does not define a lifecycle policy rule to delete failed multipart uploads. Object Lifecycle Management works by taking automated action based on rules that you define. These rules instruct Object Storage to delete uncommitted multipart uploads, move objects to a different storage tier, and delete supported resources on your behalf within a given bucket. A bucket's lifecycle rules are collectively known as an object lifecycle policy. The resources that Object Lifecycle Management supports include objects, object versions, and uncommitted or failed multipart uploads. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a lifecycle policies for your buckets refer to the Using Object Lifecycle Management section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usinglifecyclepolicies.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
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
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-failed-multipart-delete-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-failed-multipart-delete-lifecycle-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.3] Object Storage buckets should define a lifecycle policy rule to delete failed multipart uploads",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does define a lifecycle policy rule to delete failed multipart uploads.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a lifecycle policies for your buckets refer to the Using Object Lifecycle Management section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usinglifecyclepolicies.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
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
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_public_access_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.4] Object Storage buckets should not allow public access to objects
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        if bucket["public_access_type"] != "NoPublicAccess":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-public-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.4] Object Storage buckets should not allow public access to objects",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does allow public access to objects. When you create a bucket, the bucket is considered a private bucket and the access to the bucket and bucket contents requires authentication and authorization. However, Object Storage supports anonymous, unauthenticated access to a bucket that is not in a security zone. You make a bucket public by enabling read access to the bucket. Carefully assess the business requirement for public access to a bucket, such as if your bucket serves static assets needed for websites or web applications. When you enable anonymous access to a bucket, any user can obtain object metadata, download bucket objects, and optionally list bucket contents. Oracle recommends using pre-authenticated requests instead of public buckets. Pre-authenticated requests support more authorization, expiry, and scoping capabilities not possible with public buckets. This is a high priority finding to investigate! Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on safe public access patterns for your buckets refer to the Public Buckets section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#publicbuckets",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-public-access-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.4] Object Storage buckets should not allow public access to objects",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} does not allow public access to objects.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on safe public access patterns for your buckets refer to the Public Buckets section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/managingbuckets.htm#publicbuckets",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_replication_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.5] Object Storage should be configured to use object replication to promote resilience and recovery
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        if bucket["replication_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-replication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-replication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.5] Object Storage should be configured to use object replication to promote resilience and recovery",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} is not configured to use object replication. Replication provides protection from regional outages, aids in disaster recovery efforts, and addresses data redundancy compliance requirements. Maintaining multiple copies of data in regional locations closer to user access can also reduce latency. Enabling Object Storage replication is as simple as creating a replication policy on the source bucket that identifies the region and the bucket to replicate to. After the replication policy is created, the destination bucket is read-only and updated only by replication from the source bucket. Objects uploaded to a source bucket after policy creation are asynchronously replicated to the destination bucket. Objects deleted from the source bucket after policy creation are automatically deleted from the destination bucket. Objects uploaded to a source bucket before policy creation are not replicated. Replication overwrites any object in the destination bucket that has the same name as an object in the source bucket. A replicated object has the same name, metadata, ETag, and MD5 value as the object in the source bucket. The creation timestamp, modified timestamp, and archival state can be different, so these attributes are not replicated from the source. If the data stored in your bucket is deemed business- or mission-critical or if the data stored there supports an application with stringent data recovery requirements, consider using a replication policy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a replication policy for your buckets refer to the Using Replication section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingreplication.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-replication-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-replication-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.5] Object Storage should be configured to use object replication to promote resilience and recovery",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} is configured to use object replication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a replication policy for your buckets refer to the Using Replication section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingreplication.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.objectstorage")
def oci_object_storage_bucket_versioning_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.ObjectStorage.6] Object Storage should be configured to use object versioning to promote resilience and recovery
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for bucket in get_object_storage_buckets(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(bucket,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = bucket["compartment_id"]
        bucketId = bucket["id"]
        bucketName = bucket["name"]
        namespaceName = bucket["namespace"]
        createdAt = str(bucket["time_created"])

        if bucket["versioning"] == "Disabled":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-versioning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-versioning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.6] Object Storage should be configured to use object versioning to promote resilience and recovery",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} is not configured to use object replication. Object versioning provides data protection against accidental or malicious object update, overwrite, or deletion. Standard Oracle Cloud Infrastructure pricing applies to each bucket that is enabled for versioning. You are charged for all latest object versions and previous object versions (including deleted versions) stored in the bucket. Previous object versions are retained until you explicitly delete them. Object versioning does increase your storage costs. Consider using Object Lifecycle Management to help you manage object versions automatically. Object versioning is enabled at the bucket level. Versioning directs Object Storage to automatically create an object version each time a new object is uploaded, an existing object is overwritten, or when an object is deleted. You can enable object versioning at bucket creation time or later. Consider using Versioning in conjunction with Lifecycle Policies and Replication Policies to support your business' disaster recovery and business continuity requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using object versioning for your buckets refer to the Using Object Versioning section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-versioning-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{bucketId}/oci-object-storage-bucket-versioning-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.ObjectStorage.6] Object Storage should be configured to use object versioning to promote resilience and recovery",
                "Description": f"Oracle Object Storage bucket {bucketName} in Compartment {compartmentId} in {ociRegionName} is configured to use object replication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using object versioning for your buckets refer to the Using Object Versioning section of the Oracle Cloud Infrastructure Documentation for Object Storage.",
                        "Url": "https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingversioning.htm",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Storage",
                    "AssetService": "Oracle Object Storage",
                    "AssetComponent": "Bucket"
                },
                "Resources": [
                    {
                        "Type": "OciObjectStorageBucket",
                        "Id": bucketId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": bucketName,
                                "Id": bucketId,
                                "Namespace": namespaceName,
                                "CreatedAt": createdAt
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

## END ??