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
import botocore
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

# loop through ECR repos
def describe_repositories(cache, session):
    ecr = session.client("ecr")

    response = cache.get("describe_repositories")
    if response:
        return response
    cache["describe_repositories"] = ecr.describe_repositories(maxResults=1000)
    return cache["describe_repositories"]

@registry.register_check("ecr")
def ecr_repo_vuln_scan_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.1] ECR repositories should be configured to scan images on push"""
    for repo in describe_repositories(cache, session)["repositories"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if repo["imageScanningConfiguration"]["scanOnPush"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-no-scan",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ECR.1] ECR repositories should be configured to scan images on push",
                "Description": "ECR repository "
                + repoName
                + " is not configured to scan images on push. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Amazon Elastic Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-no-scan",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.1] ECR repositories should be configured to scan images on push",
                "Description": "ECR repository "
                + repoName
                + " is configured to scan images on push.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to scan on push refer to the Image Scanning section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Amazon Elastic Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("ecr")
def ecr_repo_image_lifecycle_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.2] ECR repositories should be have an image lifecycle policy configured"""
    ecr = session.client("ecr")
    for repo in describe_repositories(cache, session)["repositories"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            # this is a passing finding
            ecr.get_lifecycle_policy(repositoryName=repoName)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-lifecycle-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.2] ECR repositories should be have an image lifecycle policy configured",
                "Description": "ECR repository "
                + repoName
                + " does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Amazon Elastic Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
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
                        "ISO 27001:2013 A.12.5.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "LifecyclePolicyNotFoundException":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": repoArn + "/ecr-lifecycle-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": repoArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[ECR.2] ECR repositories should be have an image lifecycle policy configured",
                    "Description": "ECR repository "
                    + repoName
                    + " does not have an image lifecycle policy configured. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your repository should be configured to have an image lifecycle policy refer to the Amazon ECR Lifecycle Policies section in the Amazon ECR User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Containers",
                        "AssetService": "Amazon Elastic Container Registry",
                        "AssetComponent": "Repository"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEcrRepository",
                            "Id": repoArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"RepositoryName": repoName}},
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
                            "ISO 27001:2013 A.12.5.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

@registry.register_check("ecr")
def ecr_repo_permission_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.3] ECR repositories should be have a repository policy configured"""
    ecr = session.client("ecr")
    for repo in describe_repositories(cache, session)["repositories"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(repo,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            # this is a passing finding
            ecr.get_repository_policy(repositoryName=repoName)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": repoArn + "/ecr-repo-access-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": repoArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ECR.3] ECR repositories should be have a repository policy configured",
                "Description": "ECR repository "
                + repoName
                + " has a repository policy configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Amazon Elastic Container Registry",
                    "AssetComponent": "Repository"
                },
                "Resources": [
                    {
                        "Type": "AwsEcrRepository",
                        "Id": repoArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RepositoryName": repoName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "RepositoryPolicyNotFoundException":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": repoArn + "/ecr-repo-access-policy-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": repoArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[ECR.3] ECR repositories should be have a repository policy configured",
                    "Description": "ECR repository "
                    + repoName
                    + " does not have a repository policy configured. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your repository should be configured to have a repository policy refer to the Amazon ECR Repository Policies section in the Amazon ECR User Guide",
                            "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Containers",
                        "AssetService": "Amazon Elastic Container Registry",
                        "AssetComponent": "Repository"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEcrRepository",
                            "Id": repoArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"Other": {"RepositoryName": repoName}},
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-6",
                            "NIST SP 800-53 Rev. 4 AC-1",
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AC-3",
                            "NIST SP 800-53 Rev. 4 AC-16",
                            "NIST SP 800-53 Rev. 4 AC-19",
                            "NIST SP 800-53 Rev. 4 AC-24",
                            "NIST SP 800-53 Rev. 4 IA-1",
                            "NIST SP 800-53 Rev. 4 IA-2",
                            "NIST SP 800-53 Rev. 4 IA-4",
                            "NIST SP 800-53 Rev. 4 IA-5",
                            "NIST SP 800-53 Rev. 4 IA-8",
                            "NIST SP 800-53 Rev. 4 PE-2",
                            "NIST SP 800-53 Rev. 4 PS-3",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.7.1.1",
                            "ISO 27001:2013 A.9.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

@registry.register_check("ecr")
def ecr_latest_image_vuln_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities"""
    # ISO Time
    iso8601Time = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat())
    ecr = session.client("ecr")
    for repo in describe_repositories(cache, session)["repositories"]:
        # B64 encode all of the details for the Asset
        repoArn = str(repo["repositoryArn"])
        repoName = str(repo["repositoryName"])
        if repo["imageScanningConfiguration"]["scanOnPush"] == True:
            try:
                for images in ecr.describe_images(repositoryName=repoName, filter={"tagStatus": "TAGGED"}, maxResults=1000,)["imageDetails"]:
                    assetJson = json.dumps(images,default=str).encode("utf-8")
                    assetB64 = base64.b64encode(assetJson)
                    imageDigest = str(images["imageDigest"])
                    # use the first tag only as we need it to create the canonical ID for the Resource.Id in the ASFF for the Container Resource.Type
                    imageTag = str(images["imageTags"][0])
                    try:
                        imageVulnCheck = str(
                            images["imageScanFindingsSummary"]["findingSeverityCounts"]
                        )
                    except KeyError:
                        imageVulnCheck = "{}"
                    # Failing check
                    if imageVulnCheck != "{}":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:image/{repoName}:{imageTag}/ecr-latest-image-vuln-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": imageDigest,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/Vulnerabilities/CVE",
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "MEDIUM"},
                            "Confidence": 99,
                            "Title": "[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities",
                            "Description": f"The latest image {imageDigest} in the ECR repository {repoName} has {imageVulnCheck} vulnerabilities reported by ECR Basic Scans. The latest image is likely the last used or is likely active in your environment, while container vulnerabilities can be transient and harder to exploit, it is important for your security hygeine and threat reduction that active images are aggressively patched and minimized. Refer to the remediation instructions as well as your ECR Basic or Full (Inspector) scan results.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information about scanning images refer to the Image Scanning section of the Amazon ECR User Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Containers",
                                "AssetService": "Amazon Elastic Container Registry",
                                "AssetComponent": "Image"
                            },
                            "Resources": [
                                {
                                    "Type": "Container",
                                    "Id": f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:image/{repoName}:{imageTag}",
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Container": {
                                            "Name": f"{repoName}:{imageTag}",
                                            "ImageId": imageDigest
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.CM-8",
                                    "NIST SP 800-53 Rev. 4 RA-5",
                                    "AICPA TSC CC7.1",
                                    "ISO 27001:2013 A.12.6.1"
                                ]
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE"
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:image/{repoName}:{imageTag}/ecr-latest-image-vuln-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": imageDigest,
                            "AwsAccountId": awsAccountId,
                            "Types": [
                                "Software and Configuration Checks/Vulnerabilities/CVE",
                                "Software and Configuration Checks/AWS Security Best Practices",
                            ],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[ECR.4] The latest image in an ECR Repository should not have any vulnerabilities",
                            "Description": f"The latest image {imageDigest} in the ECR repository {repoName} does not have any vulnerabilities reported, good job!.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "For more information about scanning images refer to the Image Scanning section of the Amazon ECR User Guide",
                                    "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                                }
                            },
                            "ProductFields": {
                                "ProductName": "ElectricEye",
                                "Provider": "AWS",
                                "ProviderType": "CSP",
                                "ProviderAccountId": awsAccountId,
                                "AssetRegion": awsRegion,
                                "AssetDetails": assetB64,
                                "AssetClass": "Containers",
                                "AssetService": "Amazon Elastic Container Registry",
                                "AssetComponent": "Image"
                            },
                            "Resources": [
                                {
                                    "Type": "Container",
                                    "Id": f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:image/{repoName}:{imageTag}",
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "Container": {
                                            "Name": f"{repoName}:{imageTag}",
                                            "ImageId": imageDigest
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF V1.1 DE.CM-8",
                                    "NIST SP 800-53 Rev. 4 RA-5",
                                    "AICPA TSC CC7.1",
                                    "ISO 27001:2013 A.12.6.1"
                                ]
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED"
                        }
                        yield finding
            except Exception as e:
                print(e)
        else:
            pass

@registry.register_check("ecr")
def ecr_registry_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.5] ECR Registires should be have a registry policy configured to allow for cross-account recovery"""
    ecr = session.client("ecr")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    registryArn = f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:registry"
    try:
        policy = ecr.get_registry_policy()
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(policy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # This is a passing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{registryArn}/ecr-registry-access-policy-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[ECR.5] ECR Registires should be have a registry policy configured to allow for cross-account recovery",
            "Description": "ECR Registry "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " has a registry policy configured.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If your Registry should be configured to have a Registry policy refer to the Private registry permissions section in the Amazon ECR User Guide",
                    "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Containers",
                "AssetService": "Amazon Elastic Container Registry",
                "AssetComponent": "Registry"
            },
            "Resources": [
                {
                    "Type": "AwsEcrRegistry",
                    "Id": registryArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {"Other": {"RegistryId": awsAccountId}},
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
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1",
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED",
        }
        yield finding
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            assetB64 = None
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{registryArn}/ecr-registry-access-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": awsAccountId + awsRegion,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ECR.5] ECR Registires should be have a registry policy configured to allow for cross-account recovery",
                "Description": "ECR Registry "
                + awsAccountId
                + " in Region "
                + awsRegion
                + " does not have a registry policy configured. ECR uses a registry policy to grant permissions to an AWS principal, allowing the replication of the repositories from a source registry to your registry. By default, you have permission to configure cross-Region replication within your own registry. You only need to configure the registry policy if you're granting another account permission to replicate contents to your registry. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Registry should be configured to have a Registry policy refer to the Private registry permissions section in the Amazon ECR User Guide",
                        "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry-permissions.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Containers",
                    "AssetService": "Amazon Elastic Container Registry",
                    "AssetComponent": "Registry"
                },
                "Resources": [
                    {
                        "Type": "AwsEcrRegistry",
                        "Id": registryArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"RegistryId": awsAccountId}},
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
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        else:
            print(error)
    except Exception as e:
        print(e)

@registry.register_check("ecr")
def ecr_registry_backup_rules_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ECR.6] ECR Registires should use image replication to promote disaster recovery readiness"""
    ecr = session.client("ecr")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    registryDetail = ecr.describe_registry()
    registryArn = f"arn:{awsPartition}:ecr:{awsRegion}:{awsAccountId}:registry"
    if not registryDetail["replicationConfiguration"]["rules"]:
        # B64 encode all of the details for the Asset
        assetB64 = None
        # This is a failing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{registryArn}/ecr-registry-image-replication-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId + awsRegion,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[ECR.6] ECR Registires should use image replication to promote disaster recovery readiness",
            "Description": "ECR Registry "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " does not use Image replication. Registries can be configured to backup images to other Regions within your own Account or to other AWS Accounts to aid in disaster recovery readiness. Refer to the remediation instructions if this configuration is not intended",
            "Remediation": {
                "Recommendation": {
                    "Text": "If your Registry should be configured to for Private image replication refer to the Private image replication section in the Amazon ECR User Guide",
                    "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Containers",
                "AssetService": "Amazon Elastic Container Registry",
                "AssetComponent": "Registry"
            },
            "Resources": [
                {
                    "Type": "AwsEcrRegistry",
                    "Id": registryArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {"Other": {"RegistryId": awsAccountId}},
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
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1",
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding
    else:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(registryDetail,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{registryArn}/ecr-registry-image-replication-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": awsAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[ECR.6] ECR Registires should use image replication to promote disaster recovery readiness",
            "Description": "ECR Registry "
            + awsAccountId
            + " in Region "
            + awsRegion
            + " uses Image replication.",
            "Remediation": {
                "Recommendation": {
                    "Text": "If your Registry should be configured to for Private image replication refer to the Private image replication section in the Amazon ECR User Guide",
                    "Url": "https://docs.aws.amazon.com/AmazonECR/latest/userguide/replication.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Containers",
                "AssetService": "Amazon Elastic Container Registry",
                "AssetComponent": "Registry"
            },
            "Resources": [
                {
                    "Type": "AwsEcrRegistry",
                    "Id": registryArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {"Other": {"RegistryId": awsAccountId}},
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
                    "NIST SP 800-53 Rev. 4 SA-14",
                    "AICPA TSC CC3.1",
                    "AICPA TSC A1.2",
                    "ISO 27001:2013 A.11.1.4",
                    "ISO 27001:2013 A.17.1.1",
                    "ISO 27001:2013 A.17.1.2",
                    "ISO 27001:2013 A.17.2.1",
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding