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
import uuid
import boto3
from check_register import CheckRegister, accumulate_paged_results

registry = CheckRegister()
qldb = boto3.client("qldb")

@registry.register_check("qldb")
def qldb_deletion_protection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[QLDB.1] Ledgers should have deletion protection enabled"""
    ledgersList = []
    response = qldb.list_ledgers()
    ledgersList.append(response)
    while True:
        try:
            response = qldb.list_ledgers(NextToken=response["NextToken"])
            ledgersList.append(response)
        except:
            break
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for ledgers in ledgersList:
        for ledger in ledgers["Ledgers"]:
            ledgerName = ledger["Name"]
            ledgerDescription = qldb.describe_ledger(Name=ledgerName)
            deletionProtection = ledgerDescription["DeletionProtection"]
            ledgerArn = ledgerDescription["Arn"]
            generatorUuid = str(uuid.uuid4())
            if deletionProtection:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": ledgerArn + "/qldb-deletion-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[QLDB.1] Ledgers should have deletion protection enabled",
                    "Description": "Ledger " + ledgerName + " has deletion protection.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on managing ledgers refer to the Basic Operations for Amazon QLDB Ledgers section of the Amazon QLDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/qldb/latest/developerguide/ledger-management.basics.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsQldbLedger",
                            "Id": ledgerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA-14",
                            "AICPA TSC A1.2",
                            "AICPA TSC CC3.1",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": ledgerArn + "/qldb-deletion-protection-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[QLDB.1] Ledgers should have deletion protection enabled",
                    "Description": "Ledger "
                    + ledgerName
                    + " does not have deletion protection.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on managing ledgers refer to the Basic Operations for Amazon QLDB Ledgers section of the Amazon QLDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/qldb/latest/developerguide/ledger-management.basics.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsQldbLedger",
                            "Id": ledgerArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF ID.BE-5",
                            "NIST CSF PR.PT-5",
                            "NIST SP 800-53 CP-2",
                            "NIST SP 800-53 CP-11",
                            "NIST SP 800-53 SA-13",
                            "NIST SP 800-53 SA-14",
                            "AICPA TSC A1.2",
                            "AICPA TSC CC3.1",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1",
                        ],
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

@registry.register_check("qldb")
def qldb_export_export_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[QLDB.2] Journal S3 Exports should be encrypted"""
    exportList = []
    response = qldb.list_journal_s3_exports()
    exportList.append(response)
    while True:
        try:
            response = qldb.list_journal_s3_exports(NextToken=response["NextToken"])
            exportList.append(response)
        except:
            break
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for exports in exportList:
        for export in exports["JournalS3Exports"]:
            exportId = export["ExportId"]
            encryption = export["S3ExportConfiguration"]["EncryptionConfiguration"][
                "ObjectEncryptionType"
            ]
            generatorUuid = str(uuid.uuid4())
            if encryption != "NO_ENCRYPTION":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}" + "/qldb-export-export-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[QLDB.2] Journal S3 Exports should be encrypted",
                    "Description": "Export " + exportId + " is encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Journal S3 Export encryption refer to the Basic Operations for Requesting a Journal Export in QLDB section of the Amazon QLDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/qldb/latest/developerguide/export-journal.request.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsQldbExport",
                            "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}" + "/qldb-export-export-encryption-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": generatorUuid,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices"
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[QLDB.2] Journal S3 Exports should be encrypted",
                    "Description": "Export " + exportId + " is not encrypted.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "For more information on Journal S3 Export encryption refer to the Basic Operations for Requesting a Journal Export in QLDB section of the Amazon QLDB Developer Guide",
                            "Url": "https://docs.aws.amazon.com/qldb/latest/developerguide/export-journal.request.html",
                        }
                    },
                    "ProductFields": {"Product Name": "ElectricEye"},
                    "Resources": [
                        {
                            "Type": "AwsQldbExport",
                            "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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