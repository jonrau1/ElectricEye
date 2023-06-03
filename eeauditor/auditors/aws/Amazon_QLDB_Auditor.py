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
import uuid
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

@registry.register_check("qldb")
def qldb_deletion_protection_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[QLDB.1] Ledgers should have deletion protection enabled"""
    qldb = session.client("qldb")
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
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(ledgerDescription,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Quantum Ledger Database",
                        "AssetComponent": "Ledger"
                    },
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
                            "NIST CSF V1.1 PR.IP-3",
                            "NIST SP 800-53 Rev. 4 CM-3",
                            "NIST SP 800-53 Rev. 4 CM-4",
                            "NIST SP 800-53 Rev. 4 SA-10",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.12.1.2",
                            "ISO 27001:2013 A.12.5.1",
                            "ISO 27001:2013 A.12.6.2",
                            "ISO 27001:2013 A.14.2.2",
                            "ISO 27001:2013 A.14.2.3",
                            "ISO 27001:2013 A.14.2.4"
                        ]
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Quantum Ledger Database",
                        "AssetComponent": "Ledger"
                    },
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
                            "NIST CSF V1.1 PR.IP-3",
                            "NIST SP 800-53 Rev. 4 CM-3",
                            "NIST SP 800-53 Rev. 4 CM-4",
                            "NIST SP 800-53 Rev. 4 SA-10",
                            "AICPA TSC CC8.1",
                            "ISO 27001:2013 A.12.1.2",
                            "ISO 27001:2013 A.12.5.1",
                            "ISO 27001:2013 A.12.6.2",
                            "ISO 27001:2013 A.14.2.2",
                            "ISO 27001:2013 A.14.2.3",
                            "ISO 27001:2013 A.14.2.4"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

@registry.register_check("qldb")
def qldb_export_export_encryption_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[QLDB.2] Journal S3 Exports should be encrypted"""
    qldb = session.client("qldb")
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
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(export,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Quantum Ledger Database",
                        "AssetComponent": "Journal Export"
                    },
                    "Resources": [
                        {
                            "Type": "AwsQldbJournalExport",
                            "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Blockchain",
                        "AssetService": "Amazon Quantum Ledger Database",
                        "AssetComponent": "Journal Export"
                    },
                    "Resources": [
                        {
                            "Type": "AwsQldbJournalExport",
                            "Id": f"arn:{awsPartition}:qldb:{awsRegion}:{awsAccountId}:export:{exportId}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
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