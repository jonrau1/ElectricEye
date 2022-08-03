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

import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

# import boto3 clients
athena = boto3.client("athena")

# Get all Athena work groups
def list_work_groups(cache):
    response = cache.get("list_work_groups")
    if response:
        return response
    cache["list_work_groups"] = athena.list_work_groups()
    return cache["list_work_groups"]

@registry.register_check("athena")
def athena_workgroup_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Athena.1] Athena workgroups should be configured to enforce query result encryption"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for wgroup in list_work_groups(cache)["WorkGroups"]:
        workgroupName = wgroup["Name"]
        workgroupArn = f"arn:{awsPartition}:athena:{awsRegion}:{awsAccountId}:workgroup/{workgroupName}"
        # get specific details from workgroup
        wginfo = athena.get_work_group(WorkGroup=workgroupName)["WorkGroup"]
        # determine if there is an encryption - this dict will be missing if it is not
        try:
            encryptionOption = wginfo["Configuration"]["ResultConfiguration"]["EncryptionConfiguration"]["EncryptionOption"]
        except KeyError:
            encryptionOption = "NO_ENCRYPTION"
        # map the various encryption options (NO_ENCRYPTION, SSE_S3, SSE_KMS, and CSE_KMS)
        # this is a failing check (high severity)
        if encryptionOption == "NO_ENCRYPTION":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-workgroup-query-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
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
                "Title": "[Athena.1] Athena workgroups should be configured to enforce query result encryption",
                "Description": f"Athena workgroup {workgroupName} does not enforce query result encryption. You set up query result encryption using the Athena console or when using JDBC or ODBC. Workgroups allow you to enforce the encryption of query results. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption refer to the Encrypting Athena query results stored in Amazon S3 section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a failing check (low severity)
        elif encryptionOption == "SSE_S3":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-workgroup-query-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
                "AwsAccountId": awsAccountId,
                "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices",
                    "Effects/Data Exposure"
                ],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Athena.1] Athena workgroups should be configured to enforce query result encryption",
                "Description": f"Athena workgroup {workgroupName} enforces query result encryption, however it uses an AWS-managed server side encryption key. AWS-SSE encryption uses an AWS managed key which does not have the ability to add compensating controls to such as a Key Policy which can help prevent malicious access to your data. You set up query result encryption using the Athena console or when using JDBC or ODBC. Workgroups allow you to enforce the encryption of query results. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption refer to the Encrypting Athena query results stored in Amazon S3 section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a passing check
        elif encryptionOption == ("SSE_KMS" or "CSE_KMS"):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-workgroup-query-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
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
                "Title": "[Athena.1] Athena workgroups should be configured to enforce query result encryption",
                "Description": f"Athena workgroup {workgroupName} enforces query result encryption.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption refer to the Encrypting Athena query results stored in Amazon S3 section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a cautionary function in case encryption options are ever expanded
        else:
            print(f"Athena workgroup {workgroupName} has an encryption option of {encryptionOption} which was not accounted for...")
            continue

@registry.register_check("athena")
def athena_encrypted_workgroup_client_override_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Athena.2] Athena workgroups that enforce query result encryption should be configured to override client-side settings"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for wgroup in list_work_groups(cache)["WorkGroups"]:
        workgroupName = wgroup["Name"]
        workgroupArn = f"arn:{awsPartition}:athena:{awsRegion}:{awsAccountId}:workgroup/{workgroupName}"
        # get specific details from workgroup
        wginfo = athena.get_work_group(WorkGroup=workgroupName)["WorkGroup"]
        # determine if there is an encryption - this dict will be missing if it is not
        try:
            encryptionOption = wginfo["Configuration"]["ResultConfiguration"]["EncryptionConfiguration"]["EncryptionOption"]
        except KeyError:
            encryptionOption = "NO_ENCRYPTION"
        # next check the workgroup client-side override configuration, this *shouldn't* be missing, ever...but will plan for it
        try:
            overrideConfig = wginfo["Configuration"]["EnforceWorkGroupConfiguration"]
        except KeyError:
            overrideConfig = False
        # logic ladder - no encryption = fail, encryption + no-override = fail, encryption + override = pass, anything else = skip
        # this is a failing check (high - to match lacking encryption - so you double fail)
        if encryptionOption == "NO_ENCRYPTION":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-encrypted-workgroup-client-override-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
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
                "Title": "[Athena.2] Athena workgroups that enforce query result encryption should be configured to override client-side settings",
                "Description": f"Athena workgroup {workgroupName} does not enforce query result encryption at all. You set up query result encryption using the Athena console or when using JDBC or ODBC. Workgroups allow you to enforce the encryption of query results.  When you create or edit a workgroup and select the Override client-side settings field, then all queries that run in this workgroup use the workgroup encryption and query results location settings. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption refer to the Encrypting Athena query results stored in Amazon S3 section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a failing check (medium)
        elif (encryptionOption != "NO_ENCRYPTION" and overrideConfig == False):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-encrypted-workgroup-client-override-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
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
                "Title": "[Athena.2] Athena workgroups that enforce query result encryption should be configured to override client-side settings",
                "Description": f"Athena workgroup {workgroupName} enforces query result encryption but does not override client-side settings. When you create or edit a workgroup and select the Override client-side settings field, then all queries that run in this workgroup use the workgroup encryption and query results location settings. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption enforcement via client-side overrides refer to the Workgroup settings override client-side settings section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a passing check
        elif (encryptionOption != "NO_ENCRYPTION" and overrideConfig == True):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{workgroupArn}/athena-encrypted-workgroup-client-override-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": workgroupArn,
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
                "Title": "[Athena.2] Athena workgroups that enforce query result encryption should be configured to override client-side settings",
                "Description": f"Athena workgroup {workgroupName} enforces query result encryption and also overrides client-side settings.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Athena query result encryption enforcement via client-side overrides refer to the Workgroup settings override client-side settings section in the Amazon Athena User Guide.",
                        "Url": "https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsAthenaWorkGroup",
                        "Id": workgroupArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "Name": workgroupName,
                                "State": wginfo["State"],
                                "Description": wginfo["Description"],
                                "CreationTime": str(wginfo["CreationTime"])
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
        # this is a cautionary function in case something stupid happens
        else:
            print(f"Athena workgroup {workgroupName} has an encryption option or 'EnforceWorkGroupConfiguration' which was not accounted for...")
            continue

"""[Athena.3] Athena workgroups should be configured to publish metrics"""

"""[Athena.4] Athena workgroups should be configured to auto-select the latest engine version"""