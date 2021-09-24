'''
This file is part of ElectricEye.

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''

import datetime
import boto3
from check_register import CheckRegister

registry = CheckRegister()
# import boto3 clients
sagemaker = boto3.client("sagemaker")

@registry.register_check("sagemaker")
def sagemaker_notebook_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SageMaker.1] SageMaker notebook instance storage volumes should be encrypted"""
    # loop through sagemaker notebooks
    response = sagemaker.list_notebook_instances()
    mySageMakerNotebooks = response["NotebookInstances"]
    for notebooks in mySageMakerNotebooks:
        notebookName = str(notebooks["NotebookInstanceName"])
        response = sagemaker.describe_notebook_instance(NotebookInstanceName=notebookName)
        notebookArn = str(response["NotebookInstanceArn"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            notebookEncryptionCheck = str(response["KmsKeyId"])
            print(notebookEncryptionCheck)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": notebookArn + "/sagemaker-notebook-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.1] SageMaker notebook instance storage volumes should be encrypted",
                "Description": "SageMaker notebook instance " + notebookName + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker encryption and how to configure it refer to the Protect Data at Rest Using Encryption section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": notebookArn + "/sagemaker-notebook-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.1] SageMaker notebook instance storage volumes should be encrypted",
                "Description": "SageMaker notebook instance "
                + notebookName
                + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker encryption and how to configure it refer to the Protect Data at Rest Using Encryption section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
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

@registry.register_check("sagemaker")
def sagemaker_notebook_direct_internet_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SageMaker.2] SageMaker notebook instances should not have direct internet access configured"""
    # loop through sagemaker notebooks
    response = sagemaker.list_notebook_instances()
    mySageMakerNotebooks = response["NotebookInstances"]
    for notebooks in mySageMakerNotebooks:
        notebookName = str(notebooks["NotebookInstanceName"])
        response = sagemaker.describe_notebook_instance(NotebookInstanceName=notebookName)
        notebookArn = str(response["NotebookInstanceArn"])
        directInternetCheck = str(response["DirectInternetAccess"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if directInternetCheck == "Enabled":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": notebookArn + "/sagemaker-notebook-direct-internet-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.2] SageMaker notebook instances should not have direct internet access configured",
                "Description": "SageMaker notebook instance "
                + notebookName
                + " has direct internet access configured. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker infrastructure protection refer to the Connect a Notebook Instance to Resources in a VPC section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
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
                "Id": notebookArn + "/sagemaker-notebook-direct-internet-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.2] SageMaker notebook instances should not have direct internet access configured",
                "Description": "SageMaker notebook instance "
                + notebookName
                + " does not have direct internet access configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker infrastructure protection refer to the Connect a Notebook Instance to Resources in a VPC section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("sagemaker")
def sagemaker_notebook_in_vpc_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SageMaker.3] SageMaker notebook instances should be placed in a VPC"""
    # loop through sagemaker notebooks
    response = sagemaker.list_notebook_instances()
    mySageMakerNotebooks = response["NotebookInstances"]
    for notebooks in mySageMakerNotebooks:
        notebookName = str(notebooks["NotebookInstanceName"])
        response = sagemaker.describe_notebook_instance(NotebookInstanceName=notebookName)
        notebookArn = str(response["NotebookInstanceArn"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            inVpcCheck = str(response["SubnetId"])
            print(inVpcCheck)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": notebookArn + "/sagemaker-notebook-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.3] SageMaker notebook instances should be placed in a VPC",
                "Description": "SageMaker notebook instance "
                + notebookName
                + " is not in a VPC. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker infrastructure protection refer to the Connect a Notebook Instance to Resources in a VPC section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE",
            }
            yield finding
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": notebookArn + "/sagemaker-notebook-in-vpc-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": notebookArn,
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
                "Title": "[SageMaker.3] SageMaker notebook instances should be placed in a VPC",
                "Description": "SageMaker notebook instance " + notebookName + " is in a VPC.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker infrastructure protection refer to the Connect a Notebook Instance to Resources in a VPC section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-notebook-and-internet-access.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerNotebookInstance",
                        "Id": notebookArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"notebookName": notebookName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding

@registry.register_check("sagemaker")
def sagemaker_endpoint_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SageMaker.4] SageMaker endpoints should be encrypted"""
    # loop through sagemaker endpoints
    response = sagemaker.list_endpoints()
    mySageMakerEndpoints = response["Endpoints"]
    for endpoints in mySageMakerEndpoints:
        endpointName = str(endpoints["EndpointName"])
        response = sagemaker.describe_endpoint(EndpointName=endpointName)
        endpointArn = str(response["EndpointArn"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            dataCaptureEncryptionCheck = str(response["DataCaptureConfig"]["KmsKeyId"])
            print(dataCaptureEncryptionCheck)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": endpointArn + "/sagemaker-endpoint-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": endpointArn,
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
                "Title": "[SageMaker.4] SageMaker endpoints should be encrypted",
                "Description": "SageMaker endpoint " + endpointName + " is encrypted.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker encryption and how to configure it refer to the Protect Data at Rest Using Encryption section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerEndpoint",
                        "Id": endpointArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"endpointName": endpointName}},
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": endpointArn + "/sagemaker-endpoint-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": endpointArn,
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
                "Title": "[SageMaker.4] SageMaker endpoints should be encrypted",
                "Description": "SageMaker endpoint "
                + endpointName
                + " is not encrypted. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker encryption and how to configure it refer to the Protect Data at Rest Using Encryption section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/encryption-at-rest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerEndpoint",
                        "Id": endpointArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"endpointName": endpointName}},
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

@registry.register_check("sagemaker")
def sagemaker_model_network_isolation_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SageMaker.5] SageMaker models should have network isolation enabled"""
    # loop through sagemaker models
    response = sagemaker.list_models()
    mySageMakerModels = response["Models"]
    for models in mySageMakerModels:
        modelName = str(models["ModelName"])
        modelArn = str(models["ModelArn"])
        response = sagemaker.describe_model(ModelName=modelName)
        networkIsolationCheck = str(response["EnableNetworkIsolation"])
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if networkIsolationCheck == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": modelArn + "/sagemaker-model-network-isolation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": modelArn,
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
                "Title": "[SageMaker.5] SageMaker models should have network isolation enabled",
                "Description": "SageMaker model "
                + modelName
                + " does not have network isolation enabled. Refer to the remediation instructions to remediate this behavior",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker model network isolation and how to configure it refer to the Training and Inference Containers Run in Internet-Free Mode section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerModel",
                        "Id": modelArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"modelName": modelName}},
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
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
                "Id": modelArn + "/sagemaker-model-network-isolation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": modelArn,
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
                "Title": "[SageMaker.5] SageMaker models should have network isolation enabled",
                "Description": "SageMaker model " + modelName + " has network isolation enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on SageMaker model network isolation and how to configure it refer to the Training and Inference Containers Run in Internet-Free Mode section of the Amazon SageMaker Developer Guide",
                        "Url": "https://docs.aws.amazon.com/sagemaker/latest/dg/mkt-algo-model-internet-free.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSagemakerModel",
                        "Id": modelArn,
                        "Partition": "aws",
                        "Region": awsRegion,
                        "Details": {"Other": {"modelName": modelName}},
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-5",
                        "NIST SP 800-53 AC-4",
                        "NIST SP 800-53 AC-10",
                        "NIST SP 800-53 SC-7",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED",
            }
            yield finding