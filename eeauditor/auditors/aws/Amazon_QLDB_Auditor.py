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

import datetime
from dateutil import parser
import uuid

import boto3

from check_register import CheckRegister, accumulate_paged_results

registry = CheckRegister()
qldb = boto3.client("qldb")


@registry.register_check("qldb")
def qldb_deletion_protection_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
            generatorUuid = str(uuid.uuid4())
            if deletionProtection:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/qldb-deletion-protection-check",
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
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "PASSED",},
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/qldb-deletion-protection-check",
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
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "FAILED"},
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding


@registry.register_check("qldb")
def qldb_export_export_encryption_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
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
                    "Id": awsAccountId + "/qldb-export-export-encryption-check",
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
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "PASSED",},
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED",
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": awsAccountId + "/qldb-export-export-encryption-check",
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
                            "Type": "AwsAccount",
                            "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}",
                            "Partition": "aws",
                            "Region": awsRegion,
                        }
                    ],
                    "Compliance": {"Status": "FAILED"},
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE",
                }
                yield finding

