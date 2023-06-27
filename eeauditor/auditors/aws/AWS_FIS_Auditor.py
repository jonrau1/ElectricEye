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

def get_fis_experiment_templates(cache, session):
    response = cache.get("get_fis_experiment_templates")

    if response:
        return response
    
    experimentTemplates = []
    fis = session.client("fis")

    for template in fis.list_experiment_templates()["experimentTemplates"]:
        experimentTemplates.append(
            fis.get_experiment_template(id=template["id"])["experimentTemplate"]
        )
    
    cache["get_fis_experiment_templates"] = experimentTemplates
    return cache["get_fis_experiment_templates"]

@registry.register_check("fis")
def aws_fis_experiment_template_logging_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[FIS.1] Fault Injection Simulator experiment templates should enable logging"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for template in get_fis_experiment_templates(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(template,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        templateId = template["id"]
        templateArn = f"arn:{awsPartition}:fis:{awsRegion}:{awsAccountId}:experiment-template/{templateId}"
        # This is a failing check
        if "logConfiguration" not in template:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{templateArn}/aws-fis-experiment-template-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{templateArn}/aws-fis-experiment-template-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[FIS.1] Fault Injection Simulator experiment templates should enable logging",
                "Description": f"AWS Fault Injection Simulator experiment template {templateId} does not enable logging. You can use experiment logging to capture detailed information about your experiment as it runs. AWS FIS supports log delivery to the following destinations: an Amazon S3 bucket or an Amazon CloudWatch Logs log group. Experiment logging is disabled by default. To receive experiment logs for an experiment, you must create the experiment from an experiment template with logging enabled. The first time that you run an experiment that is configured to use a destination that hasn't been used previously for logging, we delay the experiment to configure log delivery to this destination, which takes about 15 seconds. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on enabling logs for your experiments refer to the Experiment logging for AWS FIS section of the AWS Fault Injection Simulator User Guide",
                        "Url": "https://docs.aws.amazon.com/fis/latest/userguide/monitoring-logging.html"
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
                    "AssetService": "AWS Fault Injection Simulator",
                    "AssetComponent": "Experiment Template"
                },
                "Resources": [
                    {
                        "Type": "AwsFisExperimentTemplate",
                        "Id": templateArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{templateArn}/aws-fis-experiment-template-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{templateArn}/aws-fis-experiment-template-logging-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[FIS.1] Fault Injection Simulator experiment templates should enable logging",
                "Description": f"AWS Fault Injection Simulator experiment template {templateId} does enable logging.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on enabling logs for your experiments refer to the Experiment logging for AWS FIS section of the AWS Fault Injection Simulator User Guide",
                        "Url": "https://docs.aws.amazon.com/fis/latest/userguide/monitoring-logging.html"
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
                    "AssetService": "AWS Fault Injection Simulator",
                    "AssetComponent": "Experiment Template"
                },
                "Resources": [
                    {
                        "Type": "AwsFisExperimentTemplate",
                        "Id": templateArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("fis")
def aws_fis_experiment_template_stop_condition_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[FIS.2] Fault Injection Simulator experiment templates should define a stop condition"""
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for template in get_fis_experiment_templates(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(template,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        templateId = template["id"]
        templateArn = f"arn:{awsPartition}:fis:{awsRegion}:{awsAccountId}:experiment-template/{templateId}"
        # Use a list comprehension to break open "stopConditions" and check for the Sources and fail on None. This is really stupid
        # we should use ["stopConditions"][0] but you never really know with AWS
        stopConditionSources = [stopper["source"] for stopper in template["stopConditions"]]
        if "none" in stopConditionSources:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{templateArn}/aws-fis-experiment-template-stop-condition-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{templateArn}/aws-fis-experiment-template-stop-condition-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[FIS.2] Fault Injection Simulator experiment templates should define a stop condition",
                "Description": f"AWS Fault Injection Simulator experiment template {templateId} does not define a stop condition. AWS Fault Injection Simulator (AWS FIS) provides controls and guardrails for you to run experiments safely on AWS workloads. A stop condition is a mechanism to stop an experiment if it reaches a threshold that you define as an Amazon CloudWatch alarm. If a stop condition is triggered during an experiment, AWS FIS stops the experiment. You cannot resume a stopped experiment. To create a stop condition, first define the steady state for your application or service. The steady state is when your application is performing optimally, defined in terms of business or technical metrics. For example, latency, CPU load, or number of retries. You can use the steady state to create a CloudWatch alarm that you can use to stop an experiment if your application or service reaches a state where its performance is not acceptable. Your account has a quota on the number of stop conditions that you can specify in an experiment template. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating stop conditions for your experiments refer to the Stop conditions for AWS FIS section of the AWS Fault Injection Simulator User Guide",
                        "Url": "https://docs.aws.amazon.com/fis/latest/userguide/stop-conditions.html"
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
                    "AssetService": "AWS Fault Injection Simulator",
                    "AssetComponent": "Experiment Template"
                },
                "Resources": [
                    {
                        "Type": "AwsFisExperimentTemplate",
                        "Id": templateArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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
                "Id": f"{templateArn}/aws-fis-experiment-template-stop-condition-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{templateArn}/aws-fis-experiment-template-stop-condition-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[FIS.2] Fault Injection Simulator experiment templates should define a stop condition",
                "Description": f"AWS Fault Injection Simulator experiment template {templateId} does define a stop condition.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For information on creating stop conditions for your experiments refer to the Stop conditions for AWS FIS section of the AWS Fault Injection Simulator User Guide",
                        "Url": "https://docs.aws.amazon.com/fis/latest/userguide/stop-conditions.html"
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
                    "AssetService": "AWS Fault Injection Simulator",
                    "AssetComponent": "Experiment Template"
                },
                "Resources": [
                    {
                        "Type": "AwsFisExperimentTemplate",
                        "Id": templateArn,
                        "Partition": awsPartition,
                        "Region": awsRegion
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