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
import time
import os
import json
import botocore
import base64
from dateutil.parser import parse
from check_register import CheckRegister

registry = CheckRegister()

dirPath = os.path.dirname(os.path.realpath(__file__))

@registry.register_check("codebuild")
def secret_scan_codebuild_envvar_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.CodeBuild.1] CodeBuild Project environment variables should not have secrets stored in Plaintext"""
    codebuild = session.client("codebuild")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # setup some reusable variables
    scanFile = f"{dirPath}/codebuild-data-sample.json"
    resultsFile = f"{dirPath}/codebuild-scan-result.json"
    scanCommand = f"detect-secrets scan {scanFile} > {resultsFile}"
    # Collect all CodeBuild Projects and send to the Batch API
    cbList = []
    for p in codebuild.list_projects()["projects"]:
        cbList.append(str(p))
    # Submit batch request
    for proj in codebuild.batch_get_projects(names=cbList)["projects"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(proj,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        # Create an empty list per loop to put "Plaintext" env vars as the SSM and Secrets Manager types will just be a name
        envvarList = []
        cbName = str(proj["name"])
        cbArn = str(proj["arn"])
        sourceType = str(proj["source"]["type"])
        for e in proj["environment"]["environmentVariables"]:
            if str(e["type"]) == "PLAINTEXT":
                # Append a dict into the envvarlist - this will be written into a new file
                envvarList.append({"name": str(e["name"]),"value": str(e["value"])})
            else:
                continue
        # Write the results out to a file
        with open(scanFile, 'w') as writejson:
            json.dump(envvarList, writejson, indent=2, default=str)
        # execute command
        os.system(scanCommand)
        time.sleep(1)
        # read the results file
        with open(resultsFile, 'r') as readjson:
            data = json.load(readjson)
        # if results is an empty dict then there are no secrets found!
        if not data["results"]:
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": cbArn + "/codebuild-env-var-secrets-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cbArn,
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
                "Title": "[Secrets.CodeBuild.1] CodeBuild Project environment variabless should not have secrets stored in Plaintext",
                "Description": "CodeBuild Project "
                + cbName
                + " does not have any secrets in Plaintext environment variables.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide.",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeBuild",
                    "AssetComponent": "Project"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": cbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": cbName,
                                "Source": {
                                    "Type": sourceType
                                }
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
        else:
            # this is a failing check - we won't actually parse the full payload of potential secrets
            # otherwise we would break the mutability of a finding...so we will sample the first one
            # and note that in the finding itself
            findingFile = list(data["results"].keys())[0]
            secretType = str(data["results"][findingFile][0]["type"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": cbArn + "/codebuild-env-var-secrets-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": cbArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[Secrets.CodeBuild.1] CodeBuild Project environment variabless should not have secrets stored in Plaintext",
                "Description": "CodeBuild Project "
                + cbName
                + " has at least one secret in Plaintext environment variables. Detect-secrets is reporting it as "
                + secretType
                + " secrets in plaintext can be leaked or exploited by unauthroized personnel who have permissions to access them and read the data. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your project should not contain plaintext environment variables refer to the Buildspec File Name and Storage Location section of the AWS CodeBuild User Guide.",
                        "Url": "https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html#build-spec-ref-syntax",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Developer Tools",
                    "AssetService": "AWS CodeBuild",
                    "AssetComponent": "Project"
                },
                "Resources": [
                    {
                        "Type": "AwsCodeBuildProject",
                        "Id": cbArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {
                            "AwsCodeBuildProject": {
                                "Name": cbName,
                                "Source": {
                                    "Type": sourceType
                                }
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
        # clear out memory and prevent duplicates from being cached
        os.system("rm " + scanFile)
        os.system("rm " + resultsFile)
        del envvarList
        del writejson
        del readjson
        del data

@registry.register_check("cloudformation")
def secret_scan_cloudformation_parameters_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.CloudFormation.1] CloudFormation Stack parameters should not have secrets stored in Plaintext"""
    cloudformation = session.client("cloudformation")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # setup some reusable variables
    scanFile = f"{dirPath}/cloudformation-data-sample.json"
    resultsFile = f"{dirPath}/cloudformation-scan-result.json"
    scanCommand = f"detect-secrets scan {scanFile} > {resultsFile}"
    # Paginate through all CFN Stacks
    stackList = []
    paginator = cloudformation.get_paginator("list_stacks")
    for page in paginator.paginate():
        for s in page["StackSummaries"]:
            stackList.append(str(s["StackName"]))

    for sn in stackList:
        try:
            for stack in cloudformation.describe_stacks(StackName=sn)["Stacks"]:
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(stack,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                stackId = str(stack["StackId"])
                stackArn = f"arn:{awsPartition}:cloudformation:{awsRegion}:{awsAccountId}:stack/{sn}/{stackId}"
                # Create an empty list per loop to put the Parameters into
                try:
                    paramList = []
                    if stack["Parameters"]:
                        for p in stack["Parameters"]:
                            paramList.append({"ParameterKey": str(p["ParameterKey"]),"ParameterValue": str(p["ParameterValue"])})
                    else:
                        continue
                except Exception as e:
                    if str(e) == "'Parameters'":
                        pass
                    else:
                        print(e)
                # Write the results out to a file
                with open(scanFile, 'w') as writejson:
                    json.dump(paramList, writejson, indent=2, default=str)
                # execute command
                os.system(scanCommand)
                time.sleep(1)
                # read the results file
                with open(resultsFile, 'r') as readjson:
                    data = json.load(readjson)
                # if results is an empty dict then there are no secrets found!
                if not data["results"]:
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": stackArn + "/cloudformation-params-secrets-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": stackArn,
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
                        "Title": "[Secrets.CloudFormation.1] CloudFormation Stack parameters should not have secrets stored in Plaintext",
                        "Description": "CloudFormation Stack "
                        + sn
                        + " does not have any secrets in Parameters.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about parameters refer to the Parameters section of the AWS CloudFormation User Guide.",
                                "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html",
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
                            "AssetService": "AWS CloudFormation",
                            "AssetComponent": "Stack"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFormationStack",
                                "Id": stackArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {
                                    "StackName": sn
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
                else:
                    # this is a failing check - we won't actually parse the full payload of potential secrets
                    # otherwise we would break the mutability of a finding...so we will sample the first one
                    # and note that in the finding itself
                    findingFile = list(data["results"].keys())[0]
                    secretType = str(data["results"][findingFile][0]["type"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": stackArn + "/cloudformation-params-secrets-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": stackArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[Secrets.CloudFormation.1] CloudFormation Stack parameters should not have secrets stored in Plaintext",
                        "Description": "CloudFormation Stack "
                        + sn
                        + " has at least one secret in Plaintext parameters. Detect-secrets is reporting it as "
                        + secretType
                        + " secrets in plaintext can be leaked or exploited by unauthroized personnel who have permissions to access them and read the data. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about parameters refer to the Parameters section of the AWS CloudFormation User Guide.",
                                "Url": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html",
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
                            "AssetService": "AWS CloudFormation",
                            "AssetComponent": "Stack"
                        },
                        "Resources": [
                            {
                                "Type": "AwsCloudFormationStack",
                                "Id": stackArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {"Other": {
                                    "StackName": sn
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
                # clear out memory and prevent duplicates from being cached
                os.system("rm " + scanFile)
                os.system("rm " + resultsFile)
                del paramList
                del writejson
                del readjson
                del data
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'ValidationError':
                continue
            else:
                print(error)
                continue

@registry.register_check("ecs")
def secret_scan_ecs_task_def_envvar_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.ECS.1] ECS Task Definition environment variables should not have secrets stored in Plaintext"""
    ecs = session.client("ecs")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # setup some reusable variables
    scanFile = f"{dirPath}/ecs-data-sample.json"
    resultsFile = f"{dirPath}/ecs-scan-result.json"
    scanCommand = f"detect-secrets scan {scanFile} > {resultsFile}"
    # Paginate through all Active ECS Task Defs
    taskList = []
    paginator = ecs.get_paginator("list_task_definitions")
    for page in paginator.paginate(status="ACTIVE"):
        for tdarn in page["taskDefinitionArns"]:
            taskList.append(str(tdarn))

    for t in taskList:
        task = ecs.describe_task_definition(taskDefinition=t)["taskDefinition"]
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(task,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        tdefFamily = str(task["family"])
        for c in task["containerDefinitions"]:
            cdefName = str(c["name"])
            # Create an empty list per loop to put the Env vars into
            cdefEnvList = []
            for e in c["environment"]:
                cdefEnvList.append({"name": str(e["name"]),"value": str(e["value"])})
            # Write the results out to a file
            with open(scanFile, 'w') as writejson:
                json.dump(cdefEnvList, writejson, indent=2, default=str)
            # execute command
            os.system(scanCommand)
            time.sleep(1)
            # read the results file
            with open(resultsFile, 'r') as readjson:
                data = json.load(readjson)
            # if results is an empty dict then there are no secrets found!
            if not data["results"]:
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": t + cdefName + "/ecs-envvar-secrets-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": t + cdefName,
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
                    "Title": "[Secrets.ECS.1] ECS Task Definition environment variables should not have secrets stored in Plaintext",
                    "Description": "ECS Task Definition family "
                    + tdefFamily
                    + " Container Definition "
                    + cdefName
                    + " does not have any secrets in Environment Variables.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about environmental variables for ECS refer to the Specifying environment variables section of the Amazon Elastic Container Service Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/taskdef-envfiles.html",
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
                        "AssetService": "Amazon Elastic Container Service (ECS)",
                        "AssetComponent": "Task Definition"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEcsTaskDefinition",
                            "Id": t,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEcsTaskDefinition": {
                                    "ContainerDefinitions": [
                                        {
                                            "Name": cdefName
                                        }
                                    ],
                                    "Family": tdefFamily,
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
            else:
                # this is a failing check - we won't actually parse the full payload of potential secrets
                # otherwise we would break the mutability of a finding...so we will sample the first one
                # and note that in the finding itself
                findingFile = list(data["results"].keys())[0]
                secretType = str(data["results"][findingFile][0]["type"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": t + cdefName + "/ecs-envvar-secrets-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": t + cdefName,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Data Exposure"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "CRITICAL"},
                    "Confidence": 99,
                    "Title": "[Secrets.ECS.1] ECS Task Definition environment variables should not have secrets stored in Plaintext",
                    "Description": "ECS Task Definition family "
                    + tdefFamily
                    + " Container Definition "
                    + cdefName
                    + " has at least one secret in Plaintext environment variables. Detect-secrets is reporting it as "
                    + secretType
                    + " secrets in plaintext can be leaked or exploited by unauthroized personnel who have permissions to access them and read the data. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To learn more about environmental variables for ECS refer to the Specifying environment variables section of the Amazon Elastic Container Service Developer Guide.",
                            "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/taskdef-envfiles.html",
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
                        "AssetService": "Amazon Elastic Container Service (ECS)",
                        "AssetComponent": "Task Definition"
                    },
                    "Resources": [
                        {
                            "Type": "AwsEcsTaskDefinition",
                            "Id": t,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsEcsTaskDefinition": {
                                    "ContainerDefinitions": [
                                        {
                                            "Name": cdefName
                                        }
                                    ],
                                    "Family": tdefFamily,
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
            # clear out memory and prevent duplicates from being cached
            os.system("rm " + scanFile)
            os.system("rm " + resultsFile)
            del cdefEnvList
            del writejson
            del readjson
            del data

@registry.register_check("ec2")
def secret_scan_ec2_userdata_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.EC2.1] EC2 User Data should not have secrets stored in Plaintext"""
    ec2 = session.client("ec2")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # setup some reusable variables
    scanFile = f"{dirPath}/ec2-data-sample.json"
    resultsFile = f"{dirPath}/ec2-scan-result.json"
    scanCommand = f"detect-secrets scan {scanFile} > {resultsFile}"
    # Paginate through Running and Stopped EC2 Instances
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[{'Name': 'instance-state-name','Values': ['running','stopped']}]):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                # B64 encode all of the details for the Asset
                assetJson = json.dumps(i,default=str).encode("utf-8")
                assetB64 = base64.b64encode(assetJson)
                instanceId = str(i["InstanceId"])
                instanceArn = str(f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}")
                instanceType = str(i["InstanceType"])
                instanceImage = str(i["ImageId"])
                subnetId = str(i["SubnetId"])
                vpcId = str(i["VpcId"])
                instanceLaunchedAt = str(i["BlockDeviceMappings"][0]["Ebs"]["AttachTime"])
                try:
                    response = ec2.describe_instance_attribute(Attribute="userData",InstanceId=instanceId)
                    idata = response["UserData"]["Value"]
                except KeyError:
                    continue
                userdata = base64.b64decode(idata)
                with open(scanFile, 'w') as writejson:
                    json.dump({"value": str(userdata)}, writejson, indent=2, default=str)
                # execute command
                os.system(scanCommand)
                time.sleep(1)
                # read the results file
                with open(resultsFile, 'r') as readjson:
                    data = json.load(readjson)
                # if results is an empty dict then there are no secrets found!
                if not data["results"]:
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-userdata-secrets-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
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
                        "Title": "[Secrets.EC2.1] EC2 User Data should not have secrets stored in Plaintext",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " does not have any secrets in Environment Variables.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about environmental variables for ECS refer to the Specifying environment variables section of the Amazon Elastic Container Service Developer Guide.",
                                "Url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/taskdef-envfiles.html",
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Amazon EC2",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": vpcId,
                                        "SubnetId": subnetId,
                                        "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
                                    }
                                },
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
                else:
                    # this is a failing check - we won't actually parse the full payload of potential secrets
                    # otherwise we would break the mutability of a finding...so we will sample the first one
                    # and note that in the finding itself
                    findingFile = list(data["results"].keys())[0]
                    secretType = str(data["results"][findingFile][0]["type"])
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": instanceArn + "/ec2-userdata-secrets-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": instanceArn,
                        "AwsAccountId": awsAccountId,
                        "Types": [
                            "Software and Configuration Checks/AWS Security Best Practices",
                            "Effects/Data Exposure"
                        ],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "CRITICAL"},
                        "Confidence": 99,
                        "Title": "[Secrets.EC2.1] EC2 User Data should not have secrets stored in Plaintext",
                        "Description": "EC2 Instance "
                        + instanceId
                        + " has at least one secret in Plaintext environment variables. Detect-secrets is reporting it as "
                        + secretType
                        + " secrets in plaintext can be leaked or exploited by unauthroized personnel who have permissions to access them and read the data. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "To learn more about working with Instance User Data refer to the Work with instance user data section of the Amazon Elastic Compute Cloud User Guide.",
                                "Url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html"
                            }
                        },
                        "ProductFields": {
                            "ProductName": "ElectricEye",
                            "Provider": "AWS",
                            "ProviderType": "CSP",
                            "ProviderAccountId": awsAccountId,
                            "AssetRegion": awsRegion,
                            "AssetDetails": assetB64,
                            "AssetClass": "Compute",
                            "AssetService": "Amazon EC2",
                            "AssetComponent": "Instance"
                        },
                        "Resources": [
                            {
                                "Type": "AwsEc2Instance",
                                "Id": instanceArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsEc2Instance": {
                                        "Type": instanceType,
                                        "ImageId": instanceImage,
                                        "VpcId": vpcId,
                                        "SubnetId": subnetId,
                                        "LaunchedAt": parse(instanceLaunchedAt).isoformat(),
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
                # clear out memory and prevent duplicates from being cached
                os.system("rm " + scanFile)
                os.system("rm " + resultsFile)
                del userdata
                del writejson
                del readjson
                del data

'''
@registry.register_check("lambda")
def secret_scan_lambda_envvar_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Secrets.Lambda.1] Lambda Function environment variables should not have secrets stored in Plaintext"""
'''