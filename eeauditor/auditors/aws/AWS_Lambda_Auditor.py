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
from dateutil import parser
import botocore
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def get_lambda_functions(cache, session):
    lambdas = session.client("lambda")
    lambdaFunctions = []
    response = cache.get("get_lambda_functions")
    if response:
        return response
    paginator = lambdas.get_paginator('list_functions')
    if paginator:
        for page in paginator.paginate():
            for function in page["Functions"]:
                lambdaFunctions.append(function)
        cache["get_lambda_functions"] = lambdaFunctions
        return cache["get_lambda_functions"]

def get_lambda_layers(cache, session):
    lambdas = session.client("lambda")
    lambdaLayers = []
    response = cache.get("get_lambda_layers")
    if response:
        return response
    paginator = lambdas.get_paginator('list_layers')
    if paginator:
        for page in paginator.paginate():
            for layer in page["Layers"]:
                lambdaLayers.append(layer)
        cache["get_lambda_layers"] = lambdaLayers
        return cache["get_lambda_layers"]

@registry.register_check("lambda")
def aws_lambda_unused_function_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.1] Lambda functions should be deleted after 30 days of no use"""
    cloudwatch = session.client("cloudwatch")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        metricResponse = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Invocations",
                            "Dimensions": [{"Name": "FunctionName", "Value": functionName},],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=datetime.datetime.now() - datetime.timedelta(days=30),
            EndTime=datetime.datetime.now(),
        )
        metrics = metricResponse["MetricDataResults"]
        for metric in metrics:
            modify_date = parser.parse(function["LastModified"])
            date_delta = datetime.datetime.now(datetime.timezone.utc) - modify_date
            if len(metric["Values"]) > 0 or date_delta.days < 30:
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{lambdaArn}/lambda-function-unused-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": lambdaArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Lambda.1] Lambda functions should be deleted after 30 days of no use",
                    "Description": f"Lambda function {functionName} has seen activity within the last 30 days.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaFunction",
                            "Id": lambdaArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaFunction": {
                                    "FunctionName": functionName
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{lambdaArn}/lambda-function-unused-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": lambdaArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Lambda.1] Lambda functions should be deleted after 30 days of no use",
                    "Description": f"Lambda function {functionName} has not been used within the last 30 days. Functions should be deleted if they are not used to avoid any potential malicious modifications and to lessen the consumption of default Lambda quotas such as stored code and number of functions.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaFunction",
                            "Id": lambdaArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaFunction": {
                                    "FunctionName": functionName
                                }
                            }
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
                            "ISO 27001:2013 A.12.5.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("lambda")
def aws_lambda_function_tracing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.2] Lambda functions should consider using active tracing with AWS X-Ray for Performance Monitoring"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        # This is a passing check
        if str(function["TracingConfig"]["Mode"]) == "Active":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": lambdaArn + "/lambda-active-tracing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Lambda.2] Lambda functions should consider using active tracing with AWS X-Ray for Performance Monitoring",
                "Description": "Lambda function "
                + functionName
                + " has Active Tracing enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your Lambda functions send trace data to X-Ray refer to the Using AWS Lambda with AWS X-Ray section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName,
                                "TracingConfig": {
                                    "Mode": str(function["TracingConfig"]["Mode"])
                                }
                            }
                        }
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": lambdaArn + "/lambda-active-tracing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Lambda.2] Lambda functions should consider using active tracing with AWS X-Ray for Performance Monitoring",
                "Description": "Lambda function "
                + functionName
                + " does not have Active Tracing enabled. Because X-Ray gives you an end-to-end view of an entire request, you can analyze latencies in your Functions and their backend services. You can use an X-Ray service map to view the latency of an entire request and that of the downstream services that are integrated with X-Ray. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure your Lambda functions send trace data to X-Ray refer to the Using AWS Lambda with AWS X-Ray section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName,
                                "TracingConfig": {
                                    "Mode": str(function["TracingConfig"]["Mode"])
                                }
                            }
                        }
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
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("lambda")
def aws_lambda_function_code_signer_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.3] Lambda functions should use code signing from AWS Signer to ensure trusted code runs in a Function"""
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        # This is a passing check
        try:
            signingJobArn = str(function["SigningJobArn"])
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{lambdaArn}/lambda-code-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Lambda.3] Lambda functions should use code signing from AWS Signer to ensure trusted code runs in a Function",
                "Description": f"Lambda function {functionName} has an AWS code signing job configured at {signingJobArn}.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure code signing for your Functions refer to the Configuring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.SC-2",
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 RA-2",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 PM-9",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.2.1", 
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.15.2.2"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding
        except KeyError:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{lambdaArn}/lambda-code-signing-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Lambda.3] Lambda functions should use code signing from AWS Signer to ensure trusted code runs in a Function",
                "Description": f"Lambda function {functionName} does not have an AWS code signing job configured. Code signing for AWS Lambda helps to ensure that only trusted code runs in your Lambda functions. When you enable code signing for a function, Lambda checks every code deployment and verifies that the code package is signed by a trusted source. While code signing and verification plays an important part in software supply chain security, the overall posture and reachability of your Lambda function alongside the vulnerability assessment of your code and embedded packages should additionally be assessed. Lambda is a difficult attack vector for adversaries to exploit, however, with the right amount of misconfigurations - depending on the business logic the function serves - they can be exploited. Code signing provides assurance that once the function package has entered into your own supply chain it has not been otherwise tampered with. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To configure code signing for your Functions refer to the Configuring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.SC-2",
                        "NIST CSF V1.1 PR.DS-6",
                        "NIST SP 800-53 Rev. 4 RA-2",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 PM-9",
                        "NIST SP 800-53 Rev. 4 SA-12",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SA-15",
                        "NIST SP 800-53 Rev. 4 SI-7",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.2.1", 
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.15.2.2"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("lambda")
def aws_public_lambda_layer_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.4] Lambda layers should not be publicly shared"""
    lambdas = session.client("lambda")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for layer in get_lambda_layers(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(layer,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        layerName = str(layer["LayerName"])
        layerArn = str(layer["LatestMatchingVersion"]["LayerVersionArn"])
        try:
            compatibleRuntimes = layer["LatestMatchingVersion"]["CompatibleRuntimes"]
        except KeyError:
            compatibleRuntimes = []
        createDate = parser.parse(layer["LatestMatchingVersion"]["CreatedDate"]).isoformat()
        layerVersion = layer["LatestMatchingVersion"]["Version"]
        # Get the layer Policy
        try:
            layerPolicy = json.loads(lambdas.get_layer_version_policy(
                LayerName=layerName,
                VersionNumber=layerVersion
            )["Policy"])
        except Exception:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{layerArn}/public-lambda-layer-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": layerArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure",
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Lambda.4] Lambda layers should not be publicly shared",
                "Description": f"Lambda layer {layerName} does not have have a policy defined. While the Layer cannot be publicly shared without a Policy, it is a best practice to apply one to apply extra identity-based access controls and to explicitly deny sharing a Layer outside of a Zone of Trust (Account, Organization). Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on sharing Lambda Layers and modifiying their permissions refer to the Configuring layer permissions section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-permissions"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Layer"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaLayerVersion",
                        "Id": layerArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaLayerVersion": {
                                "Version": layerVersion,
                                "CompatibleRuntimes": compatibleRuntimes,
                                "CreatedDate": createDate
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
        # Evaluate layer Policy
        for s in layerPolicy["Statement"]:
            principal = s["Principal"]
            effect = s["Effect"]
            try:
                conditionalPolicy = s["Condition"]["StringEquals"]["aws:PrincipalOrgID"]
                hasCondition = True
                del conditionalPolicy
            except KeyError:
                hasCondition = False
            # this evaluation logic is a failing check
            if (principal == "*" and effect == "Allow" and hasCondition == False):
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{layerArn}/public-lambda-layer-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": layerArn,
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
                    "Title": "[Lambda.4] Lambda layers should not be publicly shared",
                    "Description": f"Lambda layer {layerName} is publicly shared without specifying a conditional access policy. Inadvertently sharing Lambda layers can potentially expose business logic or sensitive details within the Layer depending on how it is configured and thus all Layer sharing should be carefully reviewed. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on sharing Lambda Layers and modifiying their permissions refer to the Configuring layer permissions section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-permissions"
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Layer"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaLayerVersion",
                            "Id": layerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaLayerVersion": {
                                    "Version": layerVersion,
                                    "CompatibleRuntimes": compatibleRuntimes,
                                    "CreatedDate": createDate
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
                    "Id": f"{layerArn}/public-lambda-layer-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": layerArn,
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
                    "Title": "[Lambda.4] Lambda layers should not be publicly shared",
                    "Description": f"Lambda layer {layerName} is not publicly shared.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on sharing Lambda Layers and modifiying their permissions refer to the Configuring layer permissions section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-permissions"
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Layer"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaLayerVersion",
                            "Id": layerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaLayerVersion": {
                                    "Version": layerVersion,
                                    "CompatibleRuntimes": compatibleRuntimes,
                                    "CreatedDate": createDate
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

@registry.register_check("lambda")
def aws_public_lambda_function_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.5] Lambda functions should not be publicly shared"""
    lambdas = session.client("lambda")
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        # Get function policy
        try:
            funcPolicy = json.loads(lambdas.get_policy(FunctionName=functionName)["Policy"])
            # Evaluate layer Policy
            for s in funcPolicy["Statement"]:
                principal = s["Principal"]
                effect = s["Effect"]
                try:
                    # check for any condition which can be "aws:PrincipalOrgId" or "aws:SourceAccount" or "aws:SourceArn"
                    conditionalPolicy = s["Condition"]
                    hasCondition = True
                    del conditionalPolicy
                except KeyError:
                    hasCondition = False
                # this evaluation logic is a failing check
                if (principal == "*" and effect == "Allow" and hasCondition == False):
                    # this is a failing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{lambdaArn}/public-lambda-function-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": lambdaArn,
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
                        "Title": "[Lambda.5] Lambda functions should not be publicly shared",
                        "Description": f"Lambda function {functionName} is allowed to be publicly invoked. While public invocation still requires understanding the Lambda function's metadata and having valid AWS credentials, functions should never be allowed to be freely invoked and should instead have a calling service or an API Gateway. Refer to the remediation instructions if this configuration is not intended.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Lambda function resource-based policies and modifiying their permissions refer to the Using resource-based policies for AWS Lambda section of the Amazon Lambda Developer Guide",
                                "Url": "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
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
                            "AssetService": "AWS Lambda",
                            "AssetComponent": "Function"
                        },
                        "Resources": [
                            {
                                "Type": "AwsLambdaFunction",
                                "Id": lambdaArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsLambdaFunction": {
                                        "FunctionName": functionName
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
                    # this is a passing check
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": f"{lambdaArn}/public-lambda-function-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": lambdaArn,
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
                        "Title": "[Lambda.5] Lambda functions should not be publicly shared",
                        "Description": f"Lambda function {functionName} is not allowed to be publicly invoked.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on Lambda function resource-based policies and modifiying their permissions refer to the Using resource-based policies for AWS Lambda section of the Amazon Lambda Developer Guide",
                                "Url": "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
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
                            "AssetService": "AWS Lambda",
                            "AssetComponent": "Function"
                        },
                        "Resources": [
                            {
                                "Type": "AwsLambdaFunction",
                                "Id": lambdaArn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "AwsLambdaFunction": {
                                        "FunctionName": functionName
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
        except botocore.exceptions.ClientError as error:
            if error.response['Error']['Code'] == 'ResourceNotFoundException':
                # this is a passing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{lambdaArn}/public-lambda-function-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": lambdaArn,
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
                    "Title": "[Lambda.5] Lambda functions should not be publicly shared",
                    "Description": f"Lambda function {functionName} is not allowed to be publicly invoked due to not having an invocation policy and is thus exempt from this check.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Lambda function resource-based policies and modifiying their permissions refer to the Using resource-based policies for AWS Lambda section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaFunction",
                            "Id": lambdaArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaFunction": {
                                    "FunctionName": functionName
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

@registry.register_check("lambda")
def aws_lambda_supported_runtimes_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.6] Lambda functions should use supported runtimes"""
    # Supported Runtimes
    supportedRuntimes = [
        'nodejs18.x',
        'nodejs16.x',
        'nodejs14.x',
        'python3.10',
        'python3.9',
        'python3.8',
        'python3.7',
        'ruby3.2', # doesn't exist...yet
        'ruby2.7', # deprecates 15 NOV 2023
        'java11',
        'java8',
        'java8.al2',
        'go1.x',
        'dotnet7',
        'dotnet6',
        'dotnet5.0',
        'provided.al2',
        'provided'
    ]
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        lambdaRuntime = str(function["Runtime"])
        if lambdaRuntime not in supportedRuntimes:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{lambdaArn}/lambda-supported-runtimes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Lambda.6] Lambda functions should use supported runtimes",
                "Description": f"Lambda function {functionName} is not using a supported runtime version. Using support runtimes is Lambda runtimes are built around a combination of operating system, programming language, and software libraries that are subject to maintenance and security updates. When a runtime component is no longer supported for security updates, Lambda deprecates the runtime. Even though you cannot create functions that use the deprecated runtime, the function is still available to process invocation events. Make sure that your Lambda functions are current and do not use out-of-date runtime environments. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the supported runtimes that this control checks for the supported languages refer to the AWS Lambda runtimes section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName
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
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{lambdaArn}/lambda-supported-runtimes-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Lambda.6] Lambda functions should use supported runtimes",
                "Description": f"Lambda function {functionName} is using a supported runtime version.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on the supported runtimes that this control checks for the supported languages refer to the AWS Lambda runtimes section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName
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

@registry.register_check("lambda")
def lambda_vpc_ha_subnets_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.7] Lambda functions in VPCs should use more than one Availability Zone to promote high availability"""
    ec2 = session.client("ec2")
    # Create empty list to hold unique Subnet IDs - for future lookup against AZs
    uSubnets = []
    # Create another empty list to hold unique AZs based on Subnets
    uAzs = []
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for function in get_lambda_functions(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(function,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        functionName = str(function["FunctionName"])
        lambdaArn = str(function["FunctionArn"])
        # check specific metadata
        try:
            # append unique Subnets to the "uSubnets" list
            for snet in function["VpcConfig"]["SubnetIds"]:
                if snet not in uSubnets:
                    uSubnets.append(snet)
                else:
                    continue
            # look up each Subnet for the Lambda function and determine the AZ-ID
            # write unique AZ-IDs into the "uAzs" list for final determination
            for subnet in ec2.describe_subnets(SubnetIds=uSubnets)["Subnets"]:
                azId = str(subnet["AvailabilityZone"])
                if azId not in uAzs:
                    uAzs.append(azId)
                else:
                    continue
            if len(uAzs) <= 1:
                # this is a failing check
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{lambdaArn}/lambda-vpc-subnet-ha-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": lambdaArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[Lambda.7] Lambda functions in VPCs should use more than one Availability Zone to promote high availability",
                    "Description": f"Lambda function {functionName} is only deployed to a Single Availability Zone. Deploying resources across multiple Availability Zones is an AWS best practice to ensure high availability within your architecture. Availability is a core pillar in the confidentiality, integrity, and availability triad security model. All Lambda functions should have a multi-Availability Zone deployment to ensure that a single zone of failure does not cause a total disruption of operations. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information Lambda function networking and HA requirements refer to the VPC networking for Lambda section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaFunction",
                            "Id": lambdaArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaFunction": {
                                    "FunctionName": functionName
                                }
                            }
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
                            "ISO 27001:2013 A.17.2.1"
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
                    "Id": f"{lambdaArn}/lambda-vpc-subnet-ha-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": lambdaArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Lambda.7] Lambda functions in VPCs should use more than one Availability Zone to promote high availability",
                    "Description": f"Lambda function {functionName} is deployed to at least two Availability Zones.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information Lambda function networking and HA requirements refer to the VPC networking for Lambda section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"
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
                        "AssetService": "AWS Lambda",
                        "AssetComponent": "Function"
                    },
                    "Resources": [
                        {
                            "Type": "AwsLambdaFunction",
                            "Id": lambdaArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsLambdaFunction": {
                                    "FunctionName": functionName
                                }
                            }
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
                            "ISO 27001:2013 A.17.2.1"
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
                "Id": f"{lambdaArn}/lambda-vpc-subnet-ha-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": lambdaArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Lambda.7] Lambda functions in VPCs should use more than one Availability Zone to promote high availability",
                "Description": f"Lambda function {functionName} is not deployed to a VPC and is thus exempt from this check.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information Lambda function networking and HA requirements refer to the VPC networking for Lambda section of the Amazon Lambda Developer Guide",
                        "Url": "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html"
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
                    "AssetService": "AWS Lambda",
                    "AssetComponent": "Function"
                },
                "Resources": [
                    {
                        "Type": "AwsLambdaFunction",
                        "Id": lambdaArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsLambdaFunction": {
                                "FunctionName": functionName
                            }
                        }
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
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding