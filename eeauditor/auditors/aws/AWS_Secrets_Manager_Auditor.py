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

registry = CheckRegister()

def list_secrets(cache, session):
    secretsmanager = session.client("secretsmanager")
    response = cache.get("list_secrets")
    if response:
        return response
    cache["list_secrets"] = secretsmanager.list_secrets(MaxResults=100)
    return cache["list_secrets"]

@registry.register_check("secretsmanager")
def secret_age_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecretsManager.1] Secrets over 90 days old should be rotated"""
    secret = list_secrets(cache, session)
    for secrets in secret["SecretList"]:
        secretArn = str(secrets["ARN"])
        secretName = str(secrets["Name"])
        lastChangedDate = secrets["LastChangedDate"]
        todaysDatetime = datetime.datetime.now(datetime.timezone.utc)
        secretAgeFinder = todaysDatetime - lastChangedDate
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        if secretAgeFinder >= datetime.timedelta(days=90):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": secretArn + "/secrets-manager-age-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": secretArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SecretsManager.1] Secrets over 90 days old should be rotated",
                "Description": secretName
                + " is over 90 days old and should be rotated. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSecretsManagerSecret",
                        "Id": secretArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSecretsManagerSecret": {"Name": secretName}}
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
                "Id": secretArn + "/secrets-manager-age-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": secretArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SecretsManager.1] Secrets over 90 days old should be rotated",
                "Description": secretName + " is over 90 days old and should be rotated.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSecretsManagerSecret",
                        "Id": secretArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSecretsManagerSecret": {"Name": secretName}}
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

@registry.register_check("secretsmanager")
def secret_changed_in_last_90_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecretsManager.2] Secrets should have automatic rotation configured"""
    secret = list_secrets(cache, session)
    for secrets in secret["SecretList"]:
        secretArn = str(secrets["ARN"])
        secretName = str(secrets["Name"])
        # ISO Time
        iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        try:
            rotationCheck = str(secrets["RotationEnabled"])
            print(rotationCheck)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": secretArn + "/secrets-manager-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": secretArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SecretsManager.2] Secrets should have automatic rotation configured",
                "Description": secretName + " has automatic rotation configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSecretsManagerSecret",
                        "Id": secretArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSecretsManagerSecret": {"Name": secretName}}
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
        except:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": secretArn + "/secrets-manager-rotation-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": secretArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SecretsManager.2] Secrets should have automatic rotation configured",
                "Description": secretName
                + " does not have automatic rotation configured. Refer to the remediation instructions if this configuration is not intended",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Secret Rotation refer to the Rotating Your AWS Secrets Manager Secrets section of the AWS Secrets Manager User Guide",
                        "Url": "https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsSecretsManagerSecret",
                        "Id": secretArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"AwsSecretsManagerSecret": {"Name": secretName}}
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