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

def get_rest_apis(cache, session):
    apigateway = session.client("apigateway")

    response = cache.get("get_rest_apis")
    if response:
        return response
    cache["get_rest_apis"] = apigateway.get_rest_apis(limit=500)
    return cache["get_rest_apis"]

@registry.register_check("apigateway")
def api_gateway_stage_metrics_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # is is possible methodSettings is empty indicating metrics are not enabled
            try:
                metricsCheck = str(apistages["methodSettings"]["*/*"]["metricsEnabled"])
            except KeyError:
                metricsCheck = "False"
            # this is a failing check
            if metricsCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-metrics-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " does not have CloudWatch metrics enabled. You can monitor API execution by using CloudWatch, which collects and processes raw data from API Gateway into readable, near-real-time metrics. These statistics are recorded for a period of 15 months so you can access historical information and gain a better perspective on how your web application or service is performing. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
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
                    "Id": apiStageArn + "/apigateway-stage-metrics-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[APIGateway.1] API Gateway Rest API Stages should have CloudWatch Metrics enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " has CloudWatch metrics enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have CloudWatch Metrics enabled refer to the Monitor API Execution with Amazon CloudWatch section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/monitoring-cloudwatch.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("apigateway")
def api_gateway_stage_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # it is possible for methodSettings to be empty indicating logging is Off
            try:
                loggingCheck = str(apistages["methodSettings"]["*/*"]["loggingLevel"])
            except KeyError:
                loggingCheck = "OFF"
            if loggingCheck == "OFF":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-api-logging-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " does not have CloudWatch API Logging enabled. To help debug issues related to request execution or client access to your API, you can enable Amazon CloudWatch Logs to log API calls. The logged data includes errors or execution traces (such as request or response parameter values or payloads), data used by Lambda authorizers (formerly known as custom authorizers), whether API keys are required, whether usage plans are enabled, and so on. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-api-logging-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[APIGateway.2] API Gateway Rest API Stages should have CloudWatch API Logging enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " has CloudWatch API Logging enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have CloudWatch API Logging enabled refer to the Set Up CloudWatch API Logging in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("apigateway")
def api_gateway_stage_cacheing_enabled_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.3] API Gateway Rest API Stages should have Caching enabled"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            # it is possible for methodSettings to be empty which indicated caching is not enabled
            try:
                cachingCheck = str(apistages["methodSettings"]["*/*"]["cachingEnabled"])
            except KeyError:
                cachingCheck = "False"
            # this is a failing check
            if cachingCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-caching-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[APIGateway.3] API Gateway Rest API Stages should have Caching enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " does not have Caching enabled. You can enable API caching in Amazon API Gateway to cache your endpoints responses. With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "NIST SP 800-53 Rev. 4 SA14",
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
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-caching-enabled-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[APIGateway.3] API Gateway Rest API Stages should have Caching enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " has Caching enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have caching enabled refer to the Enable API Caching to Enhance Responsiveness section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "NIST SP 800-53 Rev. 4 SA14",
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

@registry.register_check("apigateway")
def api_gateway_stage_cache_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            try:
                cachingEncryptionCheck = str(apistages["methodSettings"]["*/*"]["cacheDataEncrypted"])
            except KeyError:
                cachingEncryptionCheck = "False"
            # this is a failing check
            if cachingEncryptionCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-cache-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
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
                    "Title": "[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " does not have cache encryption enabled. If you choose to enable caching for a REST API, you can enable cache encryption. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                    "CacheClusterEnabled": bool('false')
                                }
                            },
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
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding
            # this is a passing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-cache-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
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
                    "Title": "[APIGateway.4] API Gateway Rest API Stages should have cache encryption enabled",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " has cache encryption enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have caching encryption enabled refer to the Override API Gateway Stage-Level Caching for Method Caching section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html#override-api-gateway-stage-cache-for-method-cache",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                    "CacheClusterEnabled": bool('true')
                                }
                            },
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
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding

@registry.register_check("apigateway")
def api_gateway_stage_xray_tracing_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.5] API Gateway Rest API Stages should have tracing enabled"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            xrayTracingCheck = str(apistages["tracingEnabled"])
            # this is a failing check
            if xrayTracingCheck == "False":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{apiStageArn}/apigateway-stage-xray-tracing-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[APIGateway.5] API Gateway Rest API Stages should have tracing enabled",
                    "Description": f"API Gateway stage {apiStageName} for Rest API {apiGwApiName} does not have tracing enabled. Because X-Ray gives you an end-to-end view of an entire request, you can analyze latencies in your APIs and their backend services. You can use an X-Ray service map to view the latency of an entire request and that of the downstream services that are integrated with X-Ray. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
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
                    "Id": f"{apiStageArn}/apigateway-stage-xray-tracing-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[APIGateway.5] API Gateway Rest API Stages should have tracing enabled",
                    "Description": f"API Gateway stage {apiStageName} for Rest API {apiGwApiName} has tracing enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should have tracing enabled refer to the Set Up X-Ray Tracing in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-tracing.html"
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                }
                            },
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
                            "ISO 27001:2013 A.16.1.7"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("apigateway")
def api_gateway_stage_waf_check_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL"""
    apigateway = session.client("apigateway")

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        response = apigateway.get_stages(restApiId=apiGwApiId)
        for apistages in response["item"]:
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(apistages,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            apiStageName = str(apistages["stageName"])
            apiStageDeploymentId = str(apistages["deploymentId"])
            apiStageArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}/stages/{apiStageName}"
            try:
                wafCheck = str(apistages["webAclArn"])
            except KeyError:
                wafCheck = "NO_WAF"
            # this is a passing check
            if wafCheck != "NO_WAF":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-waf-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
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
                    "Title": "[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " is protected by an AWS WAF Web ACL.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName,
                                    "WebAclArn": wafCheck
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1595",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1190"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
            # this is a failing check
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": apiStageArn + "/apigateway-stage-waf-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": apiStageArn,
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
                    "Title": "[APIGateway.6] API Gateway Rest API Stages should be protected by an AWS WAF Web ACL",
                    "Description": "API Gateway stage "
                    + apiStageName
                    + " for Rest API "
                    + apiGwApiName
                    + " is not protected by an AWS WAF Web ACL. You can use AWS WAF to protect your API Gateway API from common web exploits, such as SQL injection and cross-site scripting (XSS) attacks. These could affect API availability and performance, compromise security, or consume excessive resources. Refer to the remediation instructions if this configuration is not intended",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your API Gateway stage should be protected by WAF refer to the Set Up AWS WAF in API Gateway section of the Amazon API Gateway Developer Guide",
                            "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-setup-waf.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Networking",
                        "AssetService": "Amazon API Gateway",
                        "AssetComponent": "Stage"
                    },
                    "Resources": [
                        {
                            "Type": "AwsApiGatewayStage",
                            "Id": apiStageArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "AwsApiGatewayStage": {
                                    "DeploymentId": apiStageDeploymentId,
                                    "StageName": apiStageName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 CA-7",
                            "NIST SP 800-53 Rev. 4 IR-4",
                            "NIST SP 800-53 Rev. 4 SI-4",
                            "AICPA TSC CC7.2",
                            "ISO 27001:2013 A.12.4.1",
                            "ISO 27001:2013 A.16.1.1",
                            "ISO 27001:2013 A.16.1.4",
                            "MITRE ATT&CK T1595",
                            "MITRE ATT&CK T1590",
                            "MITRE ATT&CK T1190"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding

@registry.register_check("apigateway")
def api_gateway_rest_api_policy_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.7] API Gateway Rest APIs should use an API Gateway resource policy"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(restapi,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        apiRestArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}"
        try:
            apiPolicy = restapi["policy"]
        except KeyError:
            apiPolicy = "NO_POLICY"
        # This is a failing check
        if apiPolicy == "NO_POLICY":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": apiRestArn + "/apigateway-restapi-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": apiRestArn,
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
                "Title": "[APIGateway.7] API Gateway Rest APIs should use an API Gateway resource policy",
                "Description": "API Gateway Rest API "
                + apiGwApiName
                + " has an API Gateway resource policies.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your API Gateway stage should have a Policy refer to the Controlling access to an API with API Gateway resource policies section of the Amazon API Gateway Developer Guide",
                        "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon API Gateway",
                    "AssetComponent": "REST API"
                },
                "Resources": [
                    {
                        "Type": "AwsApiGatewayRestApi",
                        "Id": apiRestArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsApiGatewayRestApi": {
                                "Id": apiGwApiId,
                                "Name": apiGwApiName
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
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": apiRestArn + "/apigateway-restapi-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": apiRestArn,
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
                "Title": "[APIGateway.7] API Gateway Rest APIs should use an API Gateway resource policy",
                "Description": "API Gateway Rest API "
                + apiGwApiName
                + " does not have an API Gateway resource policies, Amazon API Gateway resource policies are JSON policy documents that you attach to an API to control whether a specified principal (typically an IAM user or role) can invoke the API. You can use API Gateway resource policies to allow your API to be securely invoked by specified source IP address ranges or CIDR blocks. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your API Gateway stage should have a Policy refer to the Controlling access to an API with API Gateway resource policies section of the Amazon API Gateway Developer Guide",
                        "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon API Gateway",
                    "AssetComponent": "REST API"
                },
                "Resources": [
                    {
                        "Type": "AwsApiGatewayRestApi",
                        "Id": apiRestArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsApiGatewayRestApi": {
                                "Id": apiGwApiId,
                                "Name": apiGwApiName
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
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("apigateway")
def api_gateway_rest_api_authorizer_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[APIGateway.8] API Gateway Rest APIs should consider authentication with an API Gateway Lambda authorizer"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for restapi in get_rest_apis(cache, session)["items"]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(restapi,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        apiGwApiId = str(restapi["id"])
        apiGwApiName = str(restapi["name"])
        apiRestArn = f"arn:{awsPartition}:apigateway:{awsRegion}::/restapis/{apiGwApiId}"
        apiKeySource = str(restapi["apiKeySource"])
        # This is a failing check
        if apiKeySource != "AUTHORIZER":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": apiRestArn + "/apigateway-restapi-authorizer-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": apiRestArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[APIGateway.8] API Gateway Rest APIs should consider authentication with an API Gateway Lambda authorizer",
                "Description": "API Gateway Rest API "
                + apiGwApiName
                + " does not have an API Gateway resource policies, a Lambda authorizer is useful if you want to implement a custom authorization scheme that uses a bearer token authentication strategy such as OAuth or SAML, or that uses request parameters to determine the caller's identity.. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your API Gateway stage should use a Lambda authorizer refer to the Use API Gateway Lambda authorizers section of the Amazon API Gateway Developer Guide",
                        "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon API Gateway",
                    "AssetComponent": "REST API"
                },
                "Resources": [
                    {
                        "Type": "AwsApiGatewayRestApi",
                        "Id": apiRestArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsApiGatewayRestApi": {
                                "Id": apiGwApiId,
                                "Name": apiGwApiName
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
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": apiRestArn + "/apigateway-restapi-authorizer-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": apiRestArn,
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
                "Title": "[APIGateway.8] API Gateway Rest APIs should consider authentication with an API Gateway Lambda authorizer",
                "Description": "API Gateway Rest API "
                + apiGwApiName
                + " does not have an API Gateway resource policies, a Lambda authorizer is useful if you want to implement a custom authorization scheme that uses a bearer token authentication strategy such as OAuth or SAML, or that uses request parameters to determine the caller's identity.. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your API Gateway stage should use a Lambda authorizer refer to the Use API Gateway Lambda authorizers section of the Amazon API Gateway Developer Guide",
                        "Url": "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Networking",
                    "AssetService": "Amazon API Gateway",
                    "AssetComponent": "REST API"
                },
                "Resources": [
                    {
                        "Type": "AwsApiGatewayRestApi",
                        "Id": apiRestArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "AwsApiGatewayRestApi": {
                                "Id": apiGwApiId,
                                "Name": apiGwApiName
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
                        "ISO 27001:2013 A.13.2.1",
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding