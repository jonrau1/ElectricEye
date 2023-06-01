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

def get_inspector_account_status(cache, session):
    response = cache.get("get_inspector_account_status")
    if response:
        return response
    
    inspector = session.client("inspector2")

    # Smash the configurations together. Why AWS made 2 different API calls is beyond me
    accountStatus = inspector.batch_get_account_status()["accounts"][0]
    dpiConfig = inspector.get_ec2_deep_inspection_configuration()
    # stupid cheeky hack
    ec2DeepInspectionPayload = {
        "orgPackagePaths": dpiConfig["orgPackagePaths"],
        "packagePaths": dpiConfig["packagePaths"],
        "status": dpiConfig["status"]
    }
    accountStatus["resourceState"]["ec2DeepInspectionConfiguration"] = ec2DeepInspectionPayload

    cache["get_inspector_account_status"] = accountStatus
    return cache["get_inspector_account_status"]

@registry.register_check("inspector2")
def aws_inspector2_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[InspectorV2.1] Amazon Inspector V2 should be enabled to conduct vulnerability assessments and software composition analyses"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    status = get_inspector_account_status(cache, session)
    inspectorArn = f"arn:{awsPartition}:inspector2:{awsRegion}:{awsAccountId}"
    assetJson = json.dumps(status, default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if status["state"]["status"] == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{inspectorArn}/inspector2-enabled-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-enabled-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[InspectorV2.1] Amazon Inspector V2 should be enabled to conduct vulnerability assessments and software composition analyses",
            "Description": f"Amazon Inspector V2 is not enabled in {awsRegion} conduct vulnerability assessments and software composition analyses. Amazon Inspector is a vulnerability management service that continuously scans your AWS workloads for software vulnerabilities and unintended network exposure. Amazon Inspector automatically discovers and scans running Amazon EC2 instances, container images in Amazon Elastic Container Registry (Amazon ECR), and AWS Lambda functions for known software vulnerabilities and unintended network exposure. With Amazon Inspector, you don't need to manually schedule or configure assessment scans. Amazon Inspector automatically discovers and begins scanning your eligible resources. Amazon Inspector continues to assess your environment throughout the lifecycle of your resources by automatically rescanning resources in response to changes that could introduce a new vulnerability, such as: installing a new package in an EC2 instance, installing a patch, and when a new common vulnerabilities and exposures (CVE) that impacts the resource is published. Unlike traditional security scanning software, Amazon Inspector has minimal impact on the performance of your fleet. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 refer to the Getting started with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "Activation"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Activation",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["state"]["status"]
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
            "Id": f"{inspectorArn}/inspector2-enabled-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-enabled-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[InspectorV2.1] Amazon Inspector V2 should be enabled to conduct vulnerability assessments and software composition analyses",
            "Description": f"Amazon Inspector V2 is enabled in {awsRegion} conduct vulnerability assessments and software composition analyses.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 refer to the Getting started with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "Activation"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Activation",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["state"]["status"]
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

@registry.register_check("inspector2")
def aws_inspector2_ec2_scanning_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[InspectorV2.2] Amazon Inspector V2 should be configured to scan EC2 instances for vulnerabilities"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    status = get_inspector_account_status(cache, session)
    inspectorArn = f"arn:{awsPartition}:inspector2:{awsRegion}:{awsAccountId}:ec2"
    assetJson = json.dumps(status, default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if status["resourceState"]["ec2"]["status"] == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{inspectorArn}/inspector2-ec2-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ec2-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[InspectorV2.2] Amazon Inspector V2 should be configured to scan EC2 instances for vulnerabilities",
            "Description": f"Amazon Inspector V2 is not configured to scan EC2 instances for vulnerabilities in {awsRegion}. Amazon Inspector scans operating system packages and programming language packages installed on your Amazon EC2 instances for vulnerabilities. Amazon Inspector also scans your EC2 instances for network reachability issues. To perform an EC2 scan Amazon Inspector extracts software package metadata from your EC2 instances. Then, Amazon Inspector compares this metadata against rules collected from security advisories to produce findings. Amazon Inspector uses AWS Systems Manager (SSM) and the SSM Agent to collect information about the software application inventory of your EC2 instances. This data is then scanned by Amazon Inspector for software vulnerabilities. Amazon Inspector can only scan for software vulnerabilities in operating systems supported by Systems Manager. Amazon Inspector does not require the SSM Agent to scan EC2 instances for open network paths, there are no prerequisites for this type of scanning. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for EC2 refer to the Scanning Amazon EC2 instances with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "EC2 Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Ec2Scanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ec2"]["status"]
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
            "Id": f"{inspectorArn}/inspector2-ec2-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ec2-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[InspectorV2.2] Amazon Inspector V2 should be configured to scan EC2 instances for vulnerabilities",
            "Description": f"Amazon Inspector V2 is configured to scan EC2 instances for vulnerabilities in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for EC2 refer to the Scanning Amazon EC2 instances with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "EC2 Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Ec2Scanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ec2"]["status"]
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

@registry.register_check("inspector2")
def aws_inspector2_ecr_scanning_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[InspectorV2.3] Amazon Inspector V2 should be configured to scan ECR repositories for vulnerabilities"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    status = get_inspector_account_status(cache, session)
    inspectorArn = f"arn:{awsPartition}:inspector2:{awsRegion}:{awsAccountId}:ecr"
    assetJson = json.dumps(status, default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if status["resourceState"]["ecr"]["status"] == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{inspectorArn}/inspector2-ecr-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ecr-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[InspectorV2.3] Amazon Inspector V2 should be configured to scan ECR repositories for vulnerabilities",
            "Description": f"Amazon Inspector V2 is not configured to scan ECR repositories for vulnerabilities in {awsRegion}. Amazon Inspector scans container images stored in Amazon ECR for software vulnerabilities to generate Package Vulnerability findings. When you activate Amazon Inspector scans for Amazon ECR, you set Amazon Inspector as your preferred scanning service for your private registry. This replaces the default Basic scanning, which is provided at no charge by Amazon ECR, with Enhanced scanning, which is provided and billed through Amazon Inspector. The enhanced scanning provided by Amazon Inspector gives you the benefit of vulnerability scanning for both operating system and programming language packages at the registry level. You can review findings discovered using enhanced scanning at the image level, for each layer of the image, on the Amazon ECR console. Additionally, you can review and work with these findings in other services not available for basic scanning findings, including AWS Security Hub and Amazon EventBridge. Enhanced scanning gives you a choice between continuous scanning or on-push scanning at the repository level. Continuous scanning includes on-push scans and automated rescans. On-push scanning scans only when you initially push an image. For both options, you can refine the scanning scope through inclusion filters. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for ECR refer to the Scanning Amazon ECR container images with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "ECR Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2EcrScanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ecr"]["status"]
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
            "Id": f"{inspectorArn}/inspector2-ecr-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ecr-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[InspectorV2.3] Amazon Inspector V2 should be configured to scan ECR repositories for vulnerabilities",
            "Description": f"Amazon Inspector V2 is configured to scan ECR repositories for vulnerabilities in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for ECR refer to the Scanning Amazon ECR container images with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ecr.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "ECR Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2EcrScanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ecr"]["status"]
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

@registry.register_check("inspector2")
def aws_inspector2_lambda_scanning_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[InspectorV2.4] Amazon Inspector V2 should be configured to scan Lambda functions and their code packages for vulnerabilities"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    status = get_inspector_account_status(cache, session)
    inspectorArn = f"arn:{awsPartition}:inspector2:{awsRegion}:{awsAccountId}:lambda"
    assetJson = json.dumps(status, default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if status["resourceState"]["lambda"]["status"] == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{inspectorArn}/inspector2-lambda-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-lambda-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[InspectorV2.4] Amazon Inspector V2 should be configured to scan Lambda functions and their code packages for vulnerabilities",
            "Description": f"Amazon Inspector V2 is not configured to scan Lambda functions and their code packages for vulnerabilities in {awsRegion}. Amazon Inspector support for AWS Lambda functions provides continuous, automated security vulnerability assessments for Lambda functions and layers. Amazon Inspector offers two types of scanning for Lambda. These scan types look for different types of vulnerabilities. Lambda standard scanning scans application dependencies within a Lambda function and its layers for package vulnerabilities. Lambda code scanning  scans the custom application code in your functions and layers for code vulnerabilities. You can either activate Lambda standard scanning or activate Lambda standard scanning together with Lambda code scanning. Upon activation, Amazon Inspector scans all Lambda functions invoked or updated in the last 90 days in your account. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for Lambda refer to the Scanning AWS Lambda functions with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "Lambda Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2LambdaScanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["lambda"]["status"]
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
            "Id": f"{inspectorArn}/inspector2-lambda-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-lambda-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[InspectorV2.4] Amazon Inspector V2 should be configured to scan Lambda functions and their code packages for vulnerabilities",
            "Description": f"Amazon Inspector V2 is configured to scan Lambda functions and their code packages for vulnerabilities in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 scanning for Lambda refer to the Scanning AWS Lambda functions with Amazon Inspector section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "Lambda Scanner"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2LambdaScanner",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["lambda"]["status"]
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

@registry.register_check("inspector2")
def aws_inspector2_ec2_deep_inspection_scanning_enabled_in_region_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[InspectorV2.5] Amazon Inspector V2 should be configured to perform deep inspection scans on EC2 instances"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    status = get_inspector_account_status(cache, session)
    inspectorArn = f"arn:{awsPartition}:inspector2:{awsRegion}:{awsAccountId}:ec2deepinspection"
    assetJson = json.dumps(status, default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if status["resourceState"]["ec2DeepInspectionConfiguration"]["status"] == "DISABLED":
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{inspectorArn}/inspector2-ec2-deep-inspection-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ec2-deep-inspection-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[InspectorV2.5] Amazon Inspector V2 should be configured to perform deep inspection scans on EC2 instances",
            "Description": f"Amazon Inspector V2 is not configured to perform deep inspection scans on EC2 instances in {awsRegion}. With Deep inspection Amazon Inspector can detect package vulnerabilities for application programming language packages in your Linux-based Amazon EC2 instances. Amazon Inspector scans default paths for programming language package libraries. You can also configure custom paths in addition to the default ones. Amazon Inspector performs Deep inspection scans using data collected from an Amazon Inspector SSM plugin. To perform Deep inspection for Linux, Amazon Inspector automatically creates the following SSM associations in your account when it activates Deep inspection: InspectorLinuxDistributor-do-not-delete and InvokeInspectorLinuxSsmPlugin-do-not-delete. Amazon Inspector collects updated application inventory from instances for Deep inspection every 6 hours. Refer to the remediation instructions to remediate this behavior.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 deep inspection scanning for EC2 refer to the Amazon Inspector Deep inspection for Amazon EC2 Linux instances section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html#deep-inspection"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "EC2 Deep Inspection Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Ec2DeepInspectionConfiguration",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ec2DeepInspectionConfiguration"]["status"]
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
            "Id": f"{inspectorArn}/inspector2-ec2-deep-inspection-scanning-in-region-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{inspectorArn}/inspector2-ec2-deep-inspection-scanning-in-region-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[InspectorV2.5] Amazon Inspector V2 should be configured to perform deep inspection scans on EC2 instances",
            "Description": f"Amazon Inspector V2 is configured to perform deep inspection scans on EC2 instances in {awsRegion}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on enabling Amazon Inspector 2 deep inspection scanning for EC2 refer to the Amazon Inspector Deep inspection for Amazon EC2 Linux instances section in the Amazon Inspector User Guide.",
                    "Url": "https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html#deep-inspection"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Amazon Inspector V2",
                "AssetComponent": "EC2 Deep Inspection Configuration"
            },
            "Resources": [
                {
                    "Type": "AwsInspectorV2Ec2DeepInspectionConfiguration",
                    "Id": inspectorArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "Status": status["resourceState"]["ec2DeepInspectionConfiguration"]["status"]
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

## EOF ??