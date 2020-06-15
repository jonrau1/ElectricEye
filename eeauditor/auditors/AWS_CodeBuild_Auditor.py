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
import os
import datetime
from auditors.Auditor import Auditor

# import boto3 clients
sts = boto3.client("sts")
codebuild = boto3.client("codebuild")
# create env vars
awsAccountId = sts.get_caller_identity()["Account"]
awsRegion = os.environ["AWS_REGION"]
# loop through all CodeBuild projects and list their attributes
response = codebuild.list_projects()
allCodebuildProjects = response["projects"]
if allCodebuildProjects:
    response = codebuild.batch_get_projects(names=allCodebuildProjects)
    myCodeBuildProjects = response["projects"]
else:
    response = ""
    myCodeBuildProjects = ""


class ArtifactEncryptionCheck(Auditor):
    def execute(self):
        for projects in myCodeBuildProjects:
            buildProjectName = str(projects["name"])
            buildProjectArn = str(projects["arn"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            # check if this project supports artifacts
            artifactCheck = str(projects["artifacts"]["type"])
            # skip projects without artifacts
            if artifactCheck == "NO_ARTIFACTS":
                print("No artifacts supported, skipping this check")
                pass
            else:
                # check if encryption for artifacts is disabled
                artifactEncryptionCheck = str(
                    projects["artifacts"]["encryptionDisabled"]
                )
                if artifactEncryptionCheck == "True":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": buildProjectArn + "/unencrypted-artifacts",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                        "Title": "[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled",
                        "Description": "CodeBuild project "
                        + buildProjectName
                        + " has artifact encryption disabled. Refer to the remediation instructions if this configuration is not intended",
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
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCodeBuildProject": {"Name": buildProjectName}
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
                        "Id": buildProjectArn + "/unencrypted-artifacts",
                        "ProductArn": "arn:aws:securityhub:"
                        + awsRegion
                        + ":"
                        + awsAccountId
                        + ":product/"
                        + awsAccountId
                        + "/default",
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
                        "Title": "[CodeBuild.1] CodeBuild projects should not have artifact encryption disabled",
                        "Description": "CodeBuild project "
                        + buildProjectName
                        + " has artifact encryption enabled.",
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
                                "Partition": "aws",
                                "Region": awsRegion,
                                "Details": {
                                    "AwsCodeBuildProject": {"Name": buildProjectName}
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


class InsecureSSLCheck(Auditor):
    def execute(self):
        for projects in myCodeBuildProjects:
            buildProjectName = str(projects["name"])
            buildProjectArn = str(projects["arn"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            # check if Insecure SSL is enabled for your Source
            sourceInsecureSslCheck = str(projects["source"]["insecureSsl"])
            if sourceInsecureSslCheck != "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": buildProjectArn + "/insecure-ssl",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
                            },
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": buildProjectArn + "/insecure-ssl",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
                            },
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
                            "ISO 27001:2013 A.14.1.3",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding


class PlaintextENVvarCheck(Auditor):
    def execute(self):
        for projects in myCodeBuildProjects:
            buildProjectName = str(projects["name"])
            buildProjectArn = str(projects["arn"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            # check if this project has any env vars
            envVarCheck = str(projects["environment"]["environmentVariables"])
            if envVarCheck == "[]":
                print("No env vars, skipping this check")
                pass
            else:
                # loop through env vars
                codeBuildEnvVars = projects["environment"]["environmentVariables"]
                for envvar in codeBuildEnvVars:
                    plaintextCheck = str(envvar["type"])
                    # identify projects that don't use parameter store or AWS secrets manager
                    if plaintextCheck == "PLAINTEXT":
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": buildProjectArn + "/plaintext-env-vars",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "Description": "CodeBuild project "
                            + buildProjectName
                            + " contains plaintext environment variables. Refer to the remediation instructions if this configuration is not intended",
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
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCodeBuildProject": {
                                            "Name": buildProjectName
                                        }
                                    },
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
                                    "ISO 27001:2013 A.9.4.3",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
                    else:
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": buildProjectArn + "/plaintext-env-vars",
                            "ProductArn": "arn:aws:securityhub:"
                            + awsRegion
                            + ":"
                            + awsAccountId
                            + ":product/"
                            + awsAccountId
                            + "/default",
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
                            "Severity": {"Label": "INFORMATIONAL"},
                            "Confidence": 99,
                            "Title": "[CodeBuild.3] CodeBuild projects should not have plaintext environment variables",
                            "Description": "CodeBuild project "
                            + buildProjectName
                            + " does not contain plaintext environment variables.",
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
                                    "Partition": "aws",
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsCodeBuildProject": {
                                            "Name": buildProjectName
                                        }
                                    },
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
                                    "ISO 27001:2013 A.9.4.3",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding


class S3LoggingEncryptionCheck(Auditor):
    def execute(self):
        for projects in myCodeBuildProjects:
            buildProjectName = str(projects["name"])
            buildProjectArn = str(projects["arn"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            # check if this project disabled s3 log encryption
            s3EncryptionCheck = str(
                projects["logsConfig"]["s3Logs"]["encryptionDisabled"]
            )
            if s3EncryptionCheck == "True":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": buildProjectArn + "/s3-encryption",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
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
                    "Description": "CodeBuild project "
                    + buildProjectName
                    + " has S3 log encryption disabled. Refer to the remediation instructions if this configuration is not intended",
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
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
                    "Id": buildProjectArn + "/s3-encryption",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
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
                    "Description": "CodeBuild project "
                    + buildProjectName
                    + " has S3 log encryption enabled.",
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
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


class CloudwatchLoggingCheck(Auditor):
    def execute(self):
        for projects in myCodeBuildProjects:
            buildProjectName = str(projects["name"])
            buildProjectArn = str(projects["arn"])
            iso8601Time = (
                datetime.datetime.utcnow()
                .replace(tzinfo=datetime.timezone.utc)
                .isoformat()
            )
            # check if this project logs to cloudwatch
            codeBuildLoggingCheck = str(
                projects["logsConfig"]["cloudWatchLogs"]["status"]
            )
            if codeBuildLoggingCheck != "ENABLED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": buildProjectArn + "/cloudwatch-logging",
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": buildProjectArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[CodeBuild.5] CodeBuild projects should have CloudWatch logging enabled",
                    "Description": "CodeBuild project "
                    + buildProjectName
                    + " has CloudWatch logging disabled. Refer to the remediation instructions if this configuration is not intended",
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
                            },
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
                    "ProductArn": "arn:aws:securityhub:"
                    + awsRegion
                    + ":"
                    + awsAccountId
                    + ":product/"
                    + awsAccountId
                    + "/default",
                    "GeneratorId": buildProjectArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
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
                            "Partition": "aws",
                            "Region": awsRegion,
                            "Details": {
                                "AwsCodeBuildProject": {"Name": buildProjectName}
                            },
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
