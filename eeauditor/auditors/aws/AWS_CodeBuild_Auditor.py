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

registry = CheckRegister()

def get_code_build_projects(cache, session):
    codebuild = session.client("codebuild")
    response = cache.get("codebuild_projects")
    if response:
        return response
    projectNames = codebuild.list_projects()["projects"]
    if projectNames:
        codebuildProjects = codebuild.batch_get_projects(names=projectNames)["projects"]
        cache["codebuild_projects"] = codebuildProjects
        return cache["codebuild_projects"]
    else:
        return {}

@registry.register_check("codebuild")
def codebuild_artifact_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if this project supports artifacts
        artifactCheck = str(projects["artifacts"]["type"])
        # skip projects without artifacts
        if artifactCheck == "NO_ARTIFACTS":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/unencrypted-artifacts",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
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
                "Title": "[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled",
                "Description": f"CodeBuild project {buildProjectName} does not use artifacts and is thus not in scope for this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should have artifact encryption enabled scroll down to item 8 in the Create a Build Project (Console) section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/create-project.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            # check if encryption for artifacts is disabled
            if str(projects["artifacts"]["encryptionDisabled"]) == "True":
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{buildProjectArn}/unencrypted-artifacts",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": buildProjectArn,
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
                    "Title": "[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled",
                    "Description": f"CodeBuild project {buildProjectName} disables artifact encryption. If your project does not encrypt artifacts other unauthorized sources, malicious or not, can access them and potentially exfiltrate or modify them. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your project should have artifact encryption enabled scroll down to item 8 in the Create a Build Project (Console) section of the AWS CodeBuild User Guide",
                            "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/create-project.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCodeBuildProject",
                            "Id": buildProjectArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                            "ISO 27001:2013 A.8.2.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{buildProjectArn}/unencrypted-artifacts",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": buildProjectArn,
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
                    "Title": "[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled",
                    "Description": f"CodeBuild project {buildProjectName} does not disable artifact encryption.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your project should have artifact encryption enabled scroll down to item 8 in the Create a Build Project (Console) section of the AWS CodeBuild User Guide",
                            "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/create-project.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCodeBuildProject",
                            "Id": buildProjectArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                            "ISO 27001:2013 A.8.2.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("codebuild")
def codebuild_insecure_ssl_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.2] CodeBuild projects should not have insecure SSL configured"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if Insecure SSL is enabled for your Source - if KeyError is thrown it means your Source
        # (or lack thereof) does not have this argument
        try:
            insecureSsl = str(projects["source"]["insecureSsl"])
        except KeyError:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/insecure-ssl",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
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
                "Title": "[CodeBuild.2] CodeBuild projects should not have insecure SSL configured",
                "Description": f"CodeBuild project {buildProjectName} does not have a source that supports the SSL setting and is thus exempt from this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have insecure SSL configured refer to the Troubleshooting CodeBuild section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html#troubleshooting-self-signed-certificate",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        if insecureSsl != "False":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/insecure-ssl",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
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
                "Title": "[CodeBuild.2] CodeBuild projects should not have insecure SSL configured",
                "Description": "CodeBuild project "
                + buildProjectName
                + " has insecure SSL configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have insecure SSL configured refer to the Troubleshooting CodeBuild section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html#troubleshooting-self-signed-certificate",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/insecure-ssl",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
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
                "Title": "[CodeBuild.2] CodeBuild projects should not have insecure SSL configured",
                "Description": "CodeBuild project "
                + buildProjectName
                + " doesnt have insecure SSL configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have insecure SSL configured refer to the Troubleshooting CodeBuild section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/troubleshooting.html#troubleshooting-self-signed-certificate",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.DS-2",
                        "NIST SP 800-53 SC-8",
                        "NIST SP 800-53 SC-11",
                        "NIST SP 800-53 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("codebuild")
def codebuild_plaintext_env_var_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.3] CodeBuild projects should not have plaintext environment variables"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if this project has any env vars
        envVars = projects["environment"]["environmentVariables"]
        if not envVars:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/plaintext-env-vars",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                    "Sensitive Data Identifications"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeBuild.3] CodeBuild projects should not have plaintext environment variables",
                "Description": f"CodeBuild project {buildProjectName} does not contain any environment variables and this thus not in scope for this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            # loop through env vars
            for envvar in envVars:
                # identify projects that don't use parameter store or AWS secrets manager
                if str(envvar["type"]) == "PLAINTEXT":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{buildProjectArn}/plaintext-env-vars",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": buildProjectArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications",
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[CodeBuild.3] CodeBuild projects should not have plaintext environment variables",
                        "Description": f"CodeBuild project {buildProjectName} contains plaintext environment variables. While not all environment variables are sensitive, you should review your project to ensure this is not the case. Look to use Systems Manager Parameter Store even for non-sensitive values to version control them centrally and not have service degradation of your project. Refer to the remediation instructions if this configuration is not intended",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide",
                                "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCodeBuildProject",
                                "Id": buildProjectArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-1",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-2",
                                "NIST SP 800-53 IA-1",
                                "NIST SP 800-53 IA-2",
                                "NIST SP 800-53 IA-3",
                                "NIST SP 800-53 IA-4",
                                "NIST SP 800-53 IA-5",
                                "NIST SP 800-53 IA-6",
                                "NIST SP 800-53 IA-7",
                                "NIST SP 800-53 IA-8",
                                "NIST SP 800-53 IA-9",
                                "NIST SP 800-53 IA-10",
                                "NIST SP 800-53 IA-11",
                                "AICPA TSC CC6.1",
                                "AICPA TSC CC6.2",
                                "ISO 27001:2013 A.9.2.1",
                                "ISO 27001:2013 A.9.2.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.2.4",
                                "ISO 27001:2013 A.9.2.6",
                                "ISO 27001:2013 A.9.3.1",
                                "ISO 27001:2013 A.9.4.2",
                                "ISO 27001:2013 A.9.4.3"
                            ]
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                    break
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{buildProjectArn}/plaintext-env-vars",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": buildProjectArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure",
                            "Sensitive Data Identifications"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[CodeBuild.3] CodeBuild projects should not have plaintext environment variables",
                        "Description": f"CodeBuild project {buildProjectName} does not have any plaintext environment variables.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide",
                                "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCodeBuildProject",
                                "Id": buildProjectArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF PR.AC-1",
                                "NIST SP 800-53 AC-1",
                                "NIST SP 800-53 AC-2",
                                "NIST SP 800-53 IA-1",
                                "NIST SP 800-53 IA-2",
                                "NIST SP 800-53 IA-3",
                                "NIST SP 800-53 IA-4",
                                "NIST SP 800-53 IA-5",
                                "NIST SP 800-53 IA-6",
                                "NIST SP 800-53 IA-7",
                                "NIST SP 800-53 IA-8",
                                "NIST SP 800-53 IA-9",
                                "NIST SP 800-53 IA-10",
                                "NIST SP 800-53 IA-11",
                                "AICPA TSC CC6.1",
                                "AICPA TSC CC6.2",
                                "ISO 27001:2013 A.9.2.1",
                                "ISO 27001:2013 A.9.2.2",
                                "ISO 27001:2013 A.9.2.3",
                                "ISO 27001:2013 A.9.2.4",
                                "ISO 27001:2013 A.9.2.6",
                                "ISO 27001:2013 A.9.3.1",
                                "ISO 27001:2013 A.9.4.2",
                                "ISO 27001:2013 A.9.4.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
                    break

@registry.register_check("codebuild")
def codebuild_s3_logging_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if this project logs to S3 to begin with
        try:
            if str(projects["logsConfig"]["s3Logs"]["status"]) == "DISABLED":
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{buildProjectArn}/s3-encryption",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": buildProjectArn,
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
                    "Title": "[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled",
                    "Description": f"CodeBuild project {buildProjectName} does not send logs to S3 and is thus exempt from this check.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                            "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsCodeBuildProject",
                            "Id": buildProjectArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                            "ISO 27001:2013 A.8.2.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                try:
                    s3EncryptionCheck = str(projects["logsConfig"]["s3Logs"]["encryptionDisabled"])
                except KeyError:
                    s3EncryptionCheck = "NotConfigured"
                if s3EncryptionCheck != "True":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{buildProjectArn}/s3-encryption",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": buildProjectArn,
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
                        "Title": "[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled",
                        "Description": f"CodeBuild project {buildProjectName} does not have S3 log encryption enabled. Unauthorized users may be able to glean sensitive data from your continuous integration projects such as a code artifacts or other sensitive information if logging is disabled. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                                "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCodeBuildProject",
                                "Id": buildProjectArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                        "Id": f"{buildProjectArn}/s3-encryption",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": buildProjectArn,
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
                        "Title": "[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled",
                        "Description": f"CodeBuild project {buildProjectName} has S3 log encryption enabled.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                                "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCodeBuildProject",
                                "Id": buildProjectArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                                "ISO 27001:2013 A.8.2.3"
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding
        except KeyError:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/s3-encryption",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
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
                "Title": "[CodeBuild.4] CodeBuild projects should not have S3 log encryption disabled",
                "Description": f"CodeBuild project {buildProjectName} does not send logs to S3 and is thus exempt from this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have S3 log encryption disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("codebuild")
def codebuild_cloudwatch_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if this project logs to cloudwatch
        try:
            codeBuildLoggingCheck = str(projects["logsConfig"]["cloudWatchLogs"]["status"])
        except KeyError:
            codeBuildLoggingCheck = "NotConfigured"
        if codeBuildLoggingCheck != "ENABLED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": buildProjectArn + "/cloudwatch-logging",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled",
                "Description": "CodeBuild project "
                + buildProjectName
                + " has CloudWatch logging disabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have CloudWatch logging disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": buildProjectArn + "/cloudwatch-logging",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled",
                "Description": "CodeBuild project "
                + buildProjectName
                + " has CloudWatch logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not have CloudWatch logging disabled refer to #20 in the Change a Build Projects Settings (AWS CLI) section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/change-project.html#change-project-console",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsCodeBuildProject": {"Name": buildProjectName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-3",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-8",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("codebuild")
def codebuild_pat_credential_usage(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.6] CodeBuild should not store any source Personal Access Tokens"""
    codebuild = session.client("codebuild")
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    srcCreds = codebuild.list_source_credentials()["sourceCredentialsInfos"]
    if not srcCreds:
        credArn = 'no_creds'
        # this is a passing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{awsAccountId}/{credArn}/pat-basicauth-cred-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{awsAccountId}/{credArn}",
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure",
                "Sensitive Data Identifications"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[CodeBuild.6] CodeBuild should not store any source Personal Access Tokens",
            "Description": f"The CodeBuild source credential for Account {awsAccountId} in region {awsRegion} does not store any source credentials and is thus exempt from this check.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on how CodeBuild accesses source provider credentials refer to the Access your source provider in CodeBuild section of the AWS CodeBuild User Guide",
                    "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/access-tokens.html",
                }
            },
            "ProductFields": {"Product Name": "ElectricEye"},
            "Resources": [
                {
                    "Type": "AWSCodeBuildSourceCredential",
                    "Id": credArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "AwsCodeBuildProject": {}
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF PR.AC-1",
                    "NIST SP 800-53 AC-1",
                    "NIST SP 800-53 AC-2",
                    "NIST SP 800-53 IA-1",
                    "NIST SP 800-53 IA-2",
                    "NIST SP 800-53 IA-3",
                    "NIST SP 800-53 IA-4",
                    "NIST SP 800-53 IA-5",
                    "NIST SP 800-53 IA-6",
                    "NIST SP 800-53 IA-7",
                    "NIST SP 800-53 IA-8",
                    "NIST SP 800-53 IA-9",
                    "NIST SP 800-53 IA-10",
                    "NIST SP 800-53 IA-11",
                    "AICPA TSC CC6.1",
                    "AICPA TSC CC6.2",
                    "ISO 27001:2013 A.9.2.1",
                    "ISO 27001:2013 A.9.2.2",
                    "ISO 27001:2013 A.9.2.3",
                    "ISO 27001:2013 A.9.2.4",
                    "ISO 27001:2013 A.9.2.6",
                    "ISO 27001:2013 A.9.3.1",
                    "ISO 27001:2013 A.9.4.2",
                    "ISO 27001:2013 A.9.4.3"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    else:
        for cred in srcCreds:
            credArn = cred["arn"]
            credType = cred["serverType"]
            authType = cred["authType"]
            # this is a failing check
            if authType == ("BASIC_AUTH" or "PERSONAL_ACCESS_TOKEN"):
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{awsAccountId}/{credArn}/pat-basicauth-cred-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{awsAccountId}/{credArn}",
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                        "Sensitive Data Identifications"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[CodeBuild.6] CodeBuild should not store any source Personal Access Tokens",
                    "Description": f"The CodeBuild source credential for Account {awsAccountId} in region {awsRegion} is storing a {credType} of the type {authType}. Storing static credentials directly within CodeBuild allows any subsequent Projects created in this Account and Region to use them. Generally, static credentials are considered unsafe and should be stored with AWS Secrets Manager or you should opt to use OAuth-based authentication into your sources. Refer to the remediation section for more information.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on how CodeBuild accesses source provider credentials refer to the Access your source provider in CodeBuild section of the AWS CodeBuild User Guide",
                            "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/access-tokens.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AWSCodeBuildSourceCredential",
                            "Id": credArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {
                                    "Source": {
                                        "Type": credType
                                    }
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-1",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-3",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-6",
                            "NIST SP 800-53 IA-7",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 IA-9",
                            "NIST SP 800-53 IA-10",
                            "NIST SP 800-53 IA-11",
                            "AICPA TSC CC6.1",
                            "AICPA TSC CC6.2",
                            "ISO 27001:2013 A.9.2.1",
                            "ISO 27001:2013 A.9.2.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.2.4",
                            "ISO 27001:2013 A.9.2.6",
                            "ISO 27001:2013 A.9.3.1",
                            "ISO 27001:2013 A.9.4.2",
                            "ISO 27001:2013 A.9.4.3"
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
                    "Id": f"{awsAccountId}/{credArn}/pat-basicauth-cred-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{awsAccountId}/{credArn}",
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure",
                        "Sensitive Data Identifications"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[CodeBuild.6] CodeBuild should not store any source Personal Access Tokens",
                    "Description": f"The CodeBuild source credential for Account {awsAccountId} in region {awsRegion} is storing an OAuth token for {credType} which is an acceptable practice.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on how CodeBuild accesses source provider credentials refer to the Access your source provider in CodeBuild section of the AWS CodeBuild User Guide",
                            "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/access-tokens.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AWSCodeBuildSourceCredential",
                            "Id": credArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {
                                    "Source": {
                                        "Type": credType
                                    }
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF PR.AC-1",
                            "NIST SP 800-53 AC-1",
                            "NIST SP 800-53 AC-2",
                            "NIST SP 800-53 IA-1",
                            "NIST SP 800-53 IA-2",
                            "NIST SP 800-53 IA-3",
                            "NIST SP 800-53 IA-4",
                            "NIST SP 800-53 IA-5",
                            "NIST SP 800-53 IA-6",
                            "NIST SP 800-53 IA-7",
                            "NIST SP 800-53 IA-8",
                            "NIST SP 800-53 IA-9",
                            "NIST SP 800-53 IA-10",
                            "NIST SP 800-53 IA-11",
                            "AICPA TSC CC6.1",
                            "AICPA TSC CC6.2",
                            "ISO 27001:2013 A.9.2.1",
                            "ISO 27001:2013 A.9.2.2",
                            "ISO 27001:2013 A.9.2.3",
                            "ISO 27001:2013 A.9.2.4",
                            "ISO 27001:2013 A.9.2.6",
                            "ISO 27001:2013 A.9.3.1",
                            "ISO 27001:2013 A.9.4.2",
                            "ISO 27001:2013 A.9.4.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("codebuild")
def codebuild_public_build_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.7] CodeBuild projects should not be publicly accessible"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # check if the build is public
        if projects["projectVisibility"] == "PUBLIC_READ":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/public-access-build-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                    "Sensitive Data Identifications"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CodeBuild.7] CodeBuild projects should not be publicly accessible",
                "Description": f"CodeBuild project {buildProjectName} is publicly accessible. When you make your project's builds available to the public, all of a project's build results, logs, and artifacts, including builds that were run when the project was private, are made available to the public. You should ensure that sensitive details are not stored within your project. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on public builds refer to the Public build projects in AWS CodeBuild section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": buildProjectName
                            }
                        }
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/public-access-build-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                    "Sensitive Data Identifications"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeBuild.7] CodeBuild projects should not be publicly accessible",
                "Description": f"CodeBuild project {buildProjectName} is not publicly accessible.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on public builds refer to the Public build projects in AWS CodeBuild section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": buildProjectName
                            }
                        }
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
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("codebuild")
def codebuild_privileged_envrionment_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[CodeBuild.8] CodeBuild projects should not allow privileged builds"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for projects in get_code_build_projects(cache, session):
        buildProjectName = str(projects["name"])
        buildProjectArn = str(projects["arn"])
        # Check for priv access
        if str(projects["environment"]["privilegedMode"]) == "True":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/privileged-environment-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "TTPs/Privilege Escalation"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[CodeBuild.8] CodeBuild projects should not allow privileged builds",
                "Description": f"CodeBuild project {buildProjectName} allows a privileged environment. Privileged builds can access the Docker volume and other admin-restricted actions on a host, but are required for access to Elastic File Systems. Review your project to ensure you absolutely require a privileged container to run. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Containers running as Privileged will have Root permissions, this should be avoided if not needed. Refer to the Build environment compute types section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": buildProjectName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{buildProjectArn}/privileged-environment-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": buildProjectArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "TTPs/Privilege Escalation"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[CodeBuild.8] CodeBuild projects should not allow privileged builds",
                "Description": f"CodeBuild project {buildProjectName} does not allow a privileged environment.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Containers running as Privileged will have Root permissions, this should be avoided if not needed. Refer to the Build environment compute types section of the AWS CodeBuild User Guide",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-compute-types.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": buildProjectArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": buildProjectName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding