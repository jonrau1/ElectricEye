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

import datetime
from dateutil import parser
import boto3
from check_register import CheckRegister

registry = CheckRegister()
lambdas = boto3.client("lambda")
cloudwatch = boto3.client("cloudwatch")
paginator = lambdas.get_paginator('list_functions')

@registry.register_check("lambda")
def unused_function_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.1] Lambda functions should be deleted after 30 days of no use"""
    iterator = paginator.paginate()
    for page in iterator:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # create env vars
        for function in page["Functions"]:
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
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": lambdaArn + "/lambda-function-unused-check",
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
                        "Description": "Lambda function "
                        + functionName
                        + " has been used or updated in the last 30 days.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                                "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                                "NIST CSF ID.AM-2",
                                "NIST SP 800-53 CM-8",
                                "NIST SP 800-53 PM-5",
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
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": lambdaArn + "/lambda-function-unused-check",
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
                        "Description": "Lambda function "
                        + functionName
                        + " has not been used or updated in the last 30 days.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "For more information on best practices for lambda functions refer to the Best Practices for Working with AWS Lambda Functions section of the Amazon Lambda Developer Guide",
                                "Url": "https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html#function-configuration",
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
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
                                "NIST CSF ID.AM-2",
                                "NIST SP 800-53 CM-8",
                                "NIST SP 800-53 PM-5",
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

@registry.register_check("lambda")
def function_tracing_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.2] Lambda functions should use active tracing with AWS X-Ray"""
    iterator = paginator.paginate()
    for page in iterator:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # create env vars
        for function in page["Functions"]:
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
                    "Title": "[Lambda.2] Lambda functions should use active tracing with AWS X-Ray",
                    "Description": "Lambda function "
                    + functionName
                    + " has Active Tracing enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To configure your Lambda functions send trace data to X-Ray refer to the Using AWS Lambda with AWS X-Ray section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                                        "TracingConfig.Mode": str(function["TracingConfig"]["Mode"])
                                    }
                                }
                            }
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
                    "Title": "[Lambda.2] Lambda functions should use active tracing with AWS X-Ray",
                    "Description": "Lambda function "
                    + functionName
                    + " does not have Active Tracing enabled. Because X-Ray gives you an end-to-end view of an entire request, you can analyze latencies in your Functions and their backend services. You can use an X-Ray service map to view the latency of an entire request and that of the downstream services that are integrated with X-Ray. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To configure your Lambda functions send trace data to X-Ray refer to the Using AWS Lambda with AWS X-Ray section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                                        "TracingConfig.Mode": str(function["TracingConfig"]["Mode"])
                                    }
                                }
                            }
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
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("lambda")
def function_code_signer_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Lambda.3] Lambda functions should use code signing from AWS Signer to ensure trusted code runs in a Function"""
    iterator = paginator.paginate()
    for page in iterator:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # create env vars
        for function in page["Functions"]:
            functionName = str(function["FunctionName"])
            lambdaArn = str(function["FunctionArn"])
            # This is a passing check
            try:
                signingJobArn = str(function["SigningJobArn"])
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": lambdaArn + "/lambda-code-signing-check",
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
                    "Description": "Lambda function "
                    + functionName
                    + " has an AWS code signing job configured at " + signingJobArn + ".",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To configure code signing for your Functions refer to the UConfiguring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF ID.SC-2",
                            "NIST SP 800-53 RA-2",
                            "NIST SP 800-53 RA-3",
                            "NIST SP 800-53 PM-9",
                            "NIST SP 800-53 SA-12",
                            "NIST SP 800-53 SA-14",
                            "NIST SP 800-53 SA-15",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.15.2.1",
                            "ISO 27001:2013 A.15.2.2",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            except:
                signingJobArn = 'NO_CODE_SIGNING_CONFIGURED'
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": lambdaArn + "/lambda-code-signing-check",
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
                    "Description": "Lambda function "
                    + functionName
                    + " does not have an AWS code signing job configured. Code signing for AWS Lambda helps to ensure that only trusted code runs in your Lambda functions. When you enable code signing for a function, Lambda checks every code deployment and verifies that the code package is signed by a trusted source. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "To configure code signing for your Functions refer to the UConfiguring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                            "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
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
                            "NIST CSF ID.SC-2",
                            "NIST SP 800-53 RA-2",
                            "NIST SP 800-53 RA-3",
                            "NIST SP 800-53 PM-9",
                            "NIST SP 800-53 SA-12",
                            "NIST SP 800-53 SA-14",
                            "NIST SP 800-53 SA-15",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.15.2.1",
                            "ISO 27001:2013 A.15.2.2",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

'''
@registry.register_check("lambda")
def public_lambda_layer_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    iterator = paginator.paginate()
    for page in iterator:
        iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        # create env vars
        for function in page["Functions"]:
            functionName = str(function["FunctionName"])
            lambdaArn = str(function["FunctionArn"])
            if function["Layers"]:
                for layer in function["Layers"]:
                    layerArn = str(layer["Arn"])
                    # Layer Policy check takes an ARN or a Name - easy game!
                    getpolicy = lambdas.get_layer_version_policy(LayerName=layerArn)["Policy"]
                    # TO DO TO DO....
                    
                    try:
                        signingJobArn = str(function["SigningJobArn"])
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": lambdaArn + "/lambda-code-signing-check",
                            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                            "GeneratorId": lambdaArn,
                            "AwsAccountId": awsAccountId,
                            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                            "FirstObservedAt": iso8601Time,
                            "CreatedAt": iso8601Time,
                            "UpdatedAt": iso8601Time,
                            "Severity": {"Label": "HIGH"},
                            "Confidence": 99,
                            "Title": "[Lambda.4] Lambda function Layers should not be publicly shared",
                            "Description": "Lambda function "
                            + functionName
                            + " has an AWS code signing job configured.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To configure code signing for your Functions refer to the UConfiguring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLambdaFunction",
                                    "Id": lambdaArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsLambdaFunction": {
                                            "FunctionName": functionName
                                        },
                                        "Other": {
                                            "SigningJobArn": signingJobArn
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "PASSED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.SC-2",
                                    "NIST SP 800-53 RA-2",
                                    "NIST SP 800-53 RA-3",
                                    "NIST SP 800-53 PM-9",
                                    "NIST SP 800-53 SA-12",
                                    "NIST SP 800-53 SA-14",
                                    "NIST SP 800-53 SA-15",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.15.2.1",
                                    "ISO 27001:2013 A.15.2.2",
                                ],
                            },
                            "Workflow": {"Status": "RESOLVED"},
                            "RecordState": "ARCHIVED",
                        }
                        yield finding
                    else:
                        signingJobArn = 'NO_CODE_SIGNING_CONFIGURED'
                        finding = {
                            "SchemaVersion": "2018-10-08",
                            "Id": lambdaArn + "/lambda-code-signing-check",
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
                            "Description": "Lambda function "
                            + functionName
                            + " does not have an AWS code signing job configured. Code signing for AWS Lambda helps to ensure that only trusted code runs in your Lambda functions. When you enable code signing for a function, Lambda checks every code deployment and verifies that the code package is signed by a trusted source. Refer to the remediation instructions if this configuration is not intended.",
                            "Remediation": {
                                "Recommendation": {
                                    "Text": "To configure code signing for your Functions refer to the UConfiguring code signing for AWS Lambda section of the Amazon Lambda Developer Guide",
                                    "Url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html"
                                }
                            },
                            "ProductFields": {"Product Name": "ElectricEye"},
                            "Resources": [
                                {
                                    "Type": "AwsLambdaFunction",
                                    "Id": lambdaArn,
                                    "Partition": awsPartition,
                                    "Region": awsRegion,
                                    "Details": {
                                        "AwsLambdaFunction": {
                                            "FunctionName": functionName
                                        },
                                        "Other": {
                                            "SigningJobArn": signingJobArn
                                        }
                                    }
                                }
                            ],
                            "Compliance": {
                                "Status": "FAILED",
                                "RelatedRequirements": [
                                    "NIST CSF ID.SC-2",
                                    "NIST SP 800-53 RA-2",
                                    "NIST SP 800-53 RA-3",
                                    "NIST SP 800-53 PM-9",
                                    "NIST SP 800-53 SA-12",
                                    "NIST SP 800-53 SA-14",
                                    "NIST SP 800-53 SA-15",
                                    "AICPA TSC CC7.2",
                                    "ISO 27001:2013 A.15.2.1",
                                    "ISO 27001:2013 A.15.2.2",
                                ],
                            },
                            "Workflow": {"Status": "NEW"},
                            "RecordState": "ACTIVE",
                        }
                        yield finding
            else:
                continue
                        '''
                