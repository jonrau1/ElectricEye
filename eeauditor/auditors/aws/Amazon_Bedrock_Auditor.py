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

def list_bedrock_foundation_models(cache, session):
    response = cache.get("list_bedrock_foundation_models")

    if response:
        return response
    
    bedrock = session.client("bedrock")

    cache["list_bedrock_foundation_models"] = bedrock.list_foundation_models()["modelSummaries"]
    return cache["list_bedrock_foundation_models"]

def list_bedrock_custom_models(cache, session):
    response = cache.get("list_bedrock_custom_models")

    if response:
        return response
    
    bedrock = session.client("bedrock")

    cache["list_bedrock_custom_models"] = bedrock.list_custom_models()["modelSummaries"]
    return cache["list_bedrock_custom_models"]

@registry.register_check("bedrock")
def bedrock_foundation_model_audit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Bedrock.1] Amazon Bedrock foundation models should be monitored for usage"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for fm in list_bedrock_foundation_models(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(fm,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        modelName = fm["modelName"]
        modelArn = fm["modelArn"]
        modelId = fm["modelId"]
        providerName = fm["providerName"]
        
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{modelArn}/bedrock-fm-usage-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": modelArn,
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
            "Title": "[Bedrock.1] Amazon Bedrock foundation models should be monitored for usage",
            "Description": f"Amazon Bedrock foundation model {modelName} (Model ID: {modelId}) is available for use from {providerName}. Amazon Bedrock is an managed Generative AI service that enables you to build, train, and deploy Artificial Intelligence models. This finding is informational only and requires no further action.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Trained on massive datasets, foundation models (FMs) are large deep learning neural networks that have changed the way data scientists approach Artificial Intelligence (ML). Rather than develop artificial intelligence (AI) from scratch, data scientists use a foundation model as a starting point to develop ML models that power new applications more quickly and cost-effectively. The term foundation model was coined by researchers to describe ML models trained on a broad spectrum of generalized and unlabeled data and capable of performing a wide variety of general tasks such as understanding language, generating text and images, and conversing in natural language.",
                    "Url": "https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Artificial Intelligence",
                "AssetService": "Amazon Bedrock",
                "AssetComponent": "Foundation Model"
            },
            "Resources": [
                {
                    "Type": "AwsBedrockFoundationModel",
                    "Id": modelArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "modelName": modelName,
                            "modelId": modelId,
                            "providerName": providerName
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
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

@registry.register_check("bedrock")
def bedrock_custom_model_audit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Bedrock.2] Amazon Bedrock custom models should be monitored for usage"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for fm in list_bedrock_custom_models(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(fm,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        modelName = fm["modelName"]
        modelArn = fm["modelArn"]
        baseModelName = fm["baseModelName"]
        
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{modelArn}/bedrock-cm-usage-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": modelArn,
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
            "Title": "[Bedrock.2] Amazon Bedrock custom models should be monitored for usage",
            "Description": f"Amazon Bedrock foundation model {modelName} is available for use, created from {baseModelName}. Amazon Bedrock is an managed Generative AI service that enables you to build, train, and deploy Artificial Intelligence models. Model customization is the process of providing training data to a model in order to improve its performance for specific use-cases. You can customize Amazon Bedrock foundation models in order to improve their performance and create a better customer experience. Amazon Bedrock currently provides the following customization methods. This finding is informational only and requires no further action.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Model customization is the process of providing training data to a model in order to improve its performance for specific use-cases. You can customize Amazon Bedrock foundation models in order to improve their performance and create a better customer experience. Amazon Bedrock currently provides the following customization methods..",
                    "Url": "https://docs.aws.amazon.com/bedrock/latest/userguide/custom-models.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Artificial Intelligence",
                "AssetService": "Amazon Bedrock",
                "AssetComponent": "Custom Model"
            },
            "Resources": [
                {
                    "Type": "AwsBedrockCustomModel",
                    "Id": modelArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "modelName": modelName,
                            "baseModelName": baseModelName
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
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

# eof