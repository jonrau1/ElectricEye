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

def get_emr_serverless_apps(cache, session):
    emrs = session.client("emr-serverless")

    response = cache.get("get_emr_serverless_apps")
    if response:
        return
    
    emrServerlessApps = []

    for apps in emrs.list_applications(states=["CREATED", "STARTED", "STOPPED"])["applications"]:
        emrApp = emrs.get_application(applicationId=apps["id"])["application"]
        emrServerlessApps.append(emrApp)

    cache["get_emr_serverless_apps"] = emrServerlessApps
    return cache["get_emr_serverless_apps"]

@registry.register_check("emr-serverless")
def emr_serverless_application_in_vpc_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR-Serverless.1] EMR Serverless applications should be configured to run within a VPC"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for emrapp in get_emr_serverless_apps(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(emrapp,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appId = emrapp["applicationId"]
        appName = emrapp["name"]
        appArn = emrapp["arn"]
        try:
            emrapp["networkConfiguration"]
        except KeyError:
            emrAppInVpc = False
        # Work off key error as the dict doesn't appear for apps without being placed in a VPC first
        if emrAppInVpc is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{appArn}/emr-serverless-application-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EMR-Serverless.1] EMR Serverless applications should be configured to run within a VPC",
                "Description": f"EMR Serverless application {appName} is not configured to run within a VPC. You can configure EMR Serverless applications to connect to your data stores within your VPC, such as Amazon Redshift clusters, Amazon RDS databases or Amazon S3 buckets with VPC endpoints. When using a VPC ensure that your Security Groups are minimized to the ports they need, and are dedicated per Application along with overhead capacity of IP addresses in your selected Subnets. Using a VPC with EMR Serverless ensures that traffic does not traverse the internet and allows you to keep downstream resources within the private network confines as well. While not using a VPC does not making your EMR Serverless application inherently at risk of unauthorized access, using a VPC is a network security best practice and can help enforce and comply with other mandated security controls. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on running EMR Serverless applications in a VPC refer to the Configuring VPC access section in the Amazon EMR Serverless User Guide.",
                        "Url": "https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/vpc-access.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Elastic MapReduce Serverless",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "AwsEmrServerlessApplication",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "ApplicationId": appId 
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
                "Id": f"{appArn}/emr-serverless-application-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EMR-Serverless.1] EMR Serverless applications should be configured to run within a VPC",
                "Description": f"EMR Serverless application {appName} is configured to run within a VPC.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on running EMR Serverless applications in a VPC refer to the Configuring VPC access section in the Amazon EMR Serverless User Guide.",
                        "Url": "https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/vpc-access.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Elastic MapReduce Serverless",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "AwsEmrServerlessApplication",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "ApplicationId": appId 
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

@registry.register_check("emr-serverless")
def emr_serverless_application_custom_container_runtime_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[EMR-Serverless.2] EMR Serverless applications should be configured to utilize custom container runtimes"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for emrapp in get_emr_serverless_apps(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(emrapp,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appId = emrapp["applicationId"]
        appName = emrapp["name"]
        appArn = emrapp["arn"]
        try:
            emrapp["imageConfiguration"]
        except KeyError:
            emrAppInVpc = False
        # Work off key error as the dict doesn't appear for apps without using a custom image first
        if emrAppInVpc is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{appArn}/emr-serverless-application-custom-container-runtime-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[EMR-Serverless.2] EMR Serverless applications should be configured to utilize custom container runtimes",
                "Description": f"EMR Serverless application {appName} is not configured to utilize custom container runtimes. You can use the default base Amazon EMR release runtime or customize the runtime for the release to include application dependencies. To customize the runtime, you must first build the custom images that you want to use. The images must be compatible with the selected Amazon EMR Release and located in the same AWS Region as your application. In the custom image, you can include application dependencies like third-party tools and libraries. You can use existing Docker image build processes or create a security-approved golden image for production workloads. Overall, the security benefit to using a custom container runtime is applying established security processes, such as image scanning and/or signing, that meet compliance and governance requirements within your organization. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using custom container runtimes with EMR Serverless refer to the Customizing an EMR Serverless image section in the Amazon EMR Serverless User Guide.",
                        "Url": "https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/application-custom-image.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Elastic MapReduce Serverless",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "AwsEmrServerlessApplication",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "ApplicationId": appId 
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-2",
                        "NIST SP 800-53 Rev. 4 SA-3",
                        "NIST SP 800-53 Rev. 4 SA-4",
                        "NIST SP 800-53 Rev. 4 SA-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SA-17",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.6.1.5",
                        "ISO 27001:2013 A.14.1.1",
                        "ISO 27001:2013 A.14.2.1",
                        "ISO 27001:2013 A.14.2.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{appArn}/emr-serverless-application-custom-container-runtime-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": appArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[EMR-Serverless.2] EMR Serverless applications should be configured to utilize custom container runtimes",
                "Description": f"EMR Serverless application {appName} is configured to utilize custom container runtimes.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using custom container runtimes with EMR Serverless refer to the Customizing an EMR Serverless image section in the Amazon EMR Serverless User Guide.",
                        "Url": "https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/application-custom-image.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Analytics",
                    "AssetService": "Amazon Elastic MapReduce Serverless",
                    "AssetComponent": "Application"
                },
                "Resources": [
                    {
                        "Type": "AwsEmrServerlessApplication",
                        "Id": appArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ApplicationName": appName,
                                "ApplicationId": appId 
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-2",
                        "NIST SP 800-53 Rev. 4 SA-3",
                        "NIST SP 800-53 Rev. 4 SA-4",
                        "NIST SP 800-53 Rev. 4 SA-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SA-17",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.6.1.5",
                        "ISO 27001:2013 A.14.1.1",
                        "ISO 27001:2013 A.14.2.1",
                        "ISO 27001:2013 A.14.2.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# EOF?