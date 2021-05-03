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
import datetime
from check_register import CheckRegister

registry = CheckRegister()

mwaa = boto3.client("mwaa")

def list_environments(cache):
    response = cache.get("list_environments")
    if response:
        return response
    cache["list_environments"] = mwaa.list_environments()
    return cache["list_environments"]

@registry.register_check("mwaa")
def mwaa_kms_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.1] Managed Apache Airflow Environments should be encrypted with a KMS CMK"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # KmsKeyId is not provided in the response if it is not there - MWAA uses SSE-S3 style encryption by default
        try:
            envKmsId = str(response["KmsKey"])
        except:
            envKmsId = "NO_KMS_CMK"
        # This is a failing check
        if envKmsId == "NO_KMS_CMK":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-kms-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
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
                "Title": "[MWAA.1] Managed Apache Airflow Environments should be encrypted with a KMS CMK",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " is not encrypted with a KMS CMK, while Managed Workflows for Apache AirFlow uses AWS-managed AES-256 encryption keys, using KMS CMKs offers more fine-grained access control and data protection over the AWS-managed option. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on KMS Encryption for MWAA and how to configure it refer to the Customer managed CMKs for Data Encryption section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/custom-keys-certs.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
                            }
                        }
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
                "Id": envArn + "/managed-workflow-apache-airflow-kms-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
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
                "Title": "[MWAA.1] Managed Apache Airflow Environments should be encrypted with a KMS CMK",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " is encrypted with a KMS CMK.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on KMS Encryption for MWAA and how to configure it refer to the Customer managed CMKs for Data Encryption section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/custom-keys-certs.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
                            }
                        }
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

@registry.register_check("mwaa")
def mwaa_public_access_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.2] Managed Apache Airflow Environments should be use permit public URL access"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check - MWAA can expand access modes in the future so we'll take IS NOT Private
        if str(response["WebserverAccessMode"]) != "PRIVATE_ONLY":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
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
                "Title": "[MWAA.2] Managed Apache Airflow Environments should be use permit public URL access",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " allows public access, this creates a public URL to access the Apache Airflow user interface in the environment. Access to this URL, while managed by AWS IAM, should be restricted to a private network and access given via a Bastion or VPC Endpoint. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow URL access and how to configure it refer to the Apache Airflow access modes section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-public-access-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
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
                "Title": "[MWAA.2] Managed Apache Airflow Environments should be use permit public URL access",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not allow public access.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow URL access and how to configure it refer to the Apache Airflow access modes section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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

@registry.register_check("mwaa")
def mwaa_dag_processing_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.3] Managed Apache Airflow Environments should have DAG Processing logs enabled"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check
        if str(response["LoggingConfiguration"]["DagProcessingLogs"]["Enabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-dag-processing-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MWAA.3] Managed Apache Airflow Environments should have DAG Processing logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not have DAG Processing Logs enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                "Id": envArn + "/managed-workflow-apache-airflow-dag-processing-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "PASSED"},
                "Confidence": 99,
                "Title": "[MWAA.3] Managed Apache Airflow Environments should have DAG Processing logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " has DAG Processing Logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("mwaa")
def mwaa_scheduler_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.4] Managed Apache Airflow Environments should have Scheduler logs enabled"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check
        if str(response["LoggingConfiguration"]["SchedulerLogs"]["Enabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-scheduler-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MWAA.4] Managed Apache Airflow Environments should have Scheduler logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not have Scheduler Logs enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                "Id": envArn + "/managed-workflow-apache-airflow-scheduler-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "PASSED"},
                "Confidence": 99,
                "Title": "[MWAA.4] Managed Apache Airflow Environments should have Scheduler logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " has Scheduler Logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("mwaa")
def mwaa_task_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.5] Managed Apache Airflow Environments should have Task logs enabled"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check
        if str(response["LoggingConfiguration"]["TaskLogs"]["Enabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-task-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MWAA.5] Managed Apache Airflow Environments should have Task logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not have Task Logs enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                "Id": envArn + "/managed-workflow-apache-airflow-task-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "PASSED"},
                "Confidence": 99,
                "Title": "[MWAA.5] Managed Apache Airflow Environments should have Task logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " has Task Logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("mwaa")
def mwaa_webserver_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.6] Managed Apache Airflow Environments should have Webserver logs enabled"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check
        if str(response["LoggingConfiguration"]["Webserver"]["Enabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-webserver-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MWAA.6] Managed Apache Airflow Environments should have Webserver logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not have Webserver Logs enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                "Id": envArn + "/managed-workflow-apache-airflow-webserver-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "PASSED"},
                "Confidence": 99,
                "Title": "[MWAA.6] Managed Apache Airflow Environments should have Webserver logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " has Webserver Logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("mwaa")
def mwaa_worker_logging_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[MWAA.7] Managed Apache Airflow Environments should have Worker logs enabled"""
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve MWAA Envs from Cache
    for env in list_environments(cache)["Environments"]:
        response = mwaa.get_environment(Name=env)["Environment"]
        envArn = str(response["Arn"])
        envClass = str(response["EnvironmentClass"])
        envName = str(response["Name"])
        # This is a failing check
        if str(response["LoggingConfiguration"]["Worker"]["Enabled"]) == "False":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": envArn + "/managed-workflow-apache-airflow-worker-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[MWAA.7] Managed Apache Airflow Environments should have Worker logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " does not have Worker Logs enabled. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                "Id": envArn + "/managed-workflow-apache-airflow-worker-logging-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": envArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "PASSED"},
                "Confidence": 99,
                "Title": "[MWAA.7] Managed Apache Airflow Environments should have Worker logs enabled",
                "Description": "Managed Apache Airflow Environment " 
                + envName + 
                " has Worker Logs enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on AirFlow logging and metrics refer to the Amazon MWAA metrics section of the Amazon Managed Workflows for Apache Airflow User Guide.",
                        "Url": "https://docs.aws.amazon.com/mwaa/latest/userguide/cw-metrics.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAirflowEnvironment",
                        "Id": envArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "EnvironmentName": envName,
                                "EnvironmentClass": envClass
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding