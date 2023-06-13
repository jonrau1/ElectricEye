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

from check_register import CheckRegister
import datetime
import base64
import json

registry = CheckRegister()

def get_elastic_transcoder_pipelines(cache, session):
    response = cache.get("get_elastic_transcoder_pipelines")
    if response:
        return response
    
    elastictranscoder = session.client("elastictranscoder")

    etPipelines = []

    for pipeline in elastictranscoder.list_pipelines()["Pipelines"]:
        etPipelines.append(
            elastictranscoder.read_pipeline(Id=pipeline["Id"])
        )
    
    cache["get_elastic_transcoder_pipelines"] = etPipelines
    return cache["get_elastic_transcoder_pipelines"]

@registry.register_check("elastictranscoder")
def amazon_elastic_transcoder_pipeline_notifications_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticTranscoder.1] Amazon Elastic Transcoder pipelines should configure at least one type of job change notification"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for pipeline in get_elastic_transcoder_pipelines(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pipeline,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        pipelineId = pipeline["Pipeline"]["Id"]
        pipelineName = pipeline["Pipeline"]["Name"]
        pipelineArn = pipeline["Pipeline"]["Arn"]
        # Check to see if ANY value is filled out. These are older AWS APIs going back to 2015 so they lack
        # the polish of either not including them or filling out "none" or None
        noAlerting = all(value == "" for value in pipeline["Pipeline"]["Notifications"].values())
        # this is a failing check
        if noAlerting is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[ElasticTranscoder.1] Amazon Elastic Transcoder pipelines should configure at least one type of job change notification",
                "Description": f"Amazon Elastic Transcoder pipeline {pipelineName} does not configure any job change notifications. AWS Elastic Transcoder (AET) can notify you when the status of a job changes. You can configure AET to send you notifications by using Amazon Simple Notification Service (Amazon SNS). Amazon SNS offers a variety of notification options, including the ability to send messages to HTTP endpoints, email addresses, and Amazon Simple Queue Service (Amazon SQS) queues. Notifications can be sent for any combination (or none) of the following changes in status. Progressing: AET has started to process a job in the pipeline. Complete: AET has finished processing a job in the pipeline. Warning: AET encountered a warning condition while processing a job in the pipeline or, Error: AET encountered an error condition while processing a job in the pipeline. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on configuring notifications and alerting for your pipelines refer to the Notifications of Job Status section of the Amazon Elastic Transcoder Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/notifications.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Media Services",
                    "AssetService": "Amazon Elastic Transcoder",
                    "AssetComponent": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsElasticTranscoderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": pipelineName,
                                "Id": pipelineId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ElasticTranscoder.1] Amazon Elastic Transcoder pipelines should configure at least one type of job change notification",
                "Description": f"Amazon Elastic Transcoder pipeline {pipelineName} does configure at least one job change notification.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on configuring notifications and alerting for your pipelines refer to the Notifications of Job Status section of the Amazon Elastic Transcoder Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/notifications.html"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Media Services",
                    "AssetService": "Amazon Elastic Transcoder",
                    "AssetComponent": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsElasticTranscoderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": pipelineName,
                                "Id": pipelineId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding 

@registry.register_check("elastictranscoder")
def amazon_elastic_transcoder_pipeline_warnings_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[ElasticTranscoder.2] Amazon Elastic Transcoder pipelines with warnings should be investigated"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for pipeline in get_elastic_transcoder_pipelines(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(pipeline,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        pipelineId = pipeline["Pipeline"]["Id"]
        pipelineName = pipeline["Pipeline"]["Name"]
        pipelineArn = pipeline["Pipeline"]["Arn"]
        if pipeline["Warnings"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[ElasticTranscoder.2] Amazon Elastic Transcoder pipelines with warnings should be investigated",
                "Description": f"Amazon Elastic Transcoder pipeline {pipelineName} has warnings should be investigated. When you create an AWS Elastic Transcoder (AET) pipeline that uses resources in other regions, AET returns one or more warnings, the pipeline is still created, but might have increased processing times and incur cross-regional charges. The warnings are in the following format: Code (6000-6008) with an associated Message such as warnings about cross-Region buckets, cross-Region SNS Topics, KMS errors, and more. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on alarm states for your pipelines refer to the Warnings sub-section of the Read Pipeline section of the Amazon Elastic Transcoder Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/get-pipeline.html#get-pipeline-responses"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Media Services",
                    "AssetService": "Amazon Elastic Transcoder",
                    "AssetComponent": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsElasticTranscoderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": pipelineName,
                                "Id": pipelineId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{pipelineArn}/elastic-transcoder-pipeline-notifications-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[ElasticTranscoder.2] Amazon Elastic Transcoder pipelines with warnings should be investigated",
                "Description": f"Amazon Elastic Transcoder pipeline {pipelineName} does not have warnings.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on alarm states for your pipelines refer to the Warnings sub-section of the Read Pipeline section of the Amazon Elastic Transcoder Developer Guide",
                        "Url": "https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/get-pipeline.html#get-pipeline-responses"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "AWS",
                    "ProviderType": "CSP",
                    "ProviderAccountId": awsAccountId,
                    "AssetRegion": awsRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Media Services",
                    "AssetService": "Amazon Elastic Transcoder",
                    "AssetComponent": "Pipeline"
                },
                "Resources": [
                    {
                        "Type": "AwsElasticTranscoderPipeline",
                        "Id": pipelineArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": pipelineName,
                                "Id": pipelineId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## EOF ??