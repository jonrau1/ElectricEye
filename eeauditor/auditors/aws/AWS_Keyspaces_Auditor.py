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

import botocore
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def gather_keyspaces_tables(cache, session):
    keyspaces = session.client("keyspaces")
    response = cache.get("gather_keyspaces_tables")
    if response:
        return response
    awsKeyspaceInfo = []
    # AWS-managed Keyspaces - we need to ignore these
    defaultKeyspaceNames = [
        'system_schema',
        'system_schema_mcs',
        'system'
    ]

    # First, paginate all Keyspace names and pass them to another Paginator which will attempt to enumerate all Tables
    # Then write both of the data points to a list to be used for all Checks within this Auditor
    # We will also not include any Keyspace Name that corresponds to AWS-managed system Keyspaces
    try:
        keyspace_paginator = keyspaces.get_paginator("list_keyspaces")
        table_paginator = keyspaces.get_paginator("list_tables")
        keyspace_iterator = keyspace_paginator.paginate()
        for page in keyspace_iterator:
            for k in page["keyspaces"]:
                keyspaceName = k["keyspaceName"]
                if keyspaceName not in defaultKeyspaceNames:
                    # Now get all of the tables per Keyspace - setup a new iterator
                    table_iterator = table_paginator.paginate(keyspaceName=keyspaceName)
                    for page in table_iterator:
                        for t in page["tables"]:
                            tableName = t["tableName"]
                            # Write dict of Keyspace Name & Table Name to list
                            keyspacesDict = {
                                "KeyspaceName": keyspaceName,
                                "TableName": tableName
                            }
                            awsKeyspaceInfo.append(keyspacesDict)
    except botocore.exceptions.ClientError as error:
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            cache["gather_keyspaces_tables"] = {}
            return cache["gather_keyspaces_tables"]
    except botocore.exceptions.ValidationException:
        cache["gather_keyspaces_tables"] = {}
        return cache["gather_keyspaces_tables"]

    del keyspace_iterator
    del keyspace_paginator
    del table_iterator
    del table_paginator

    cache["gather_keyspaces_tables"] = awsKeyspaceInfo
    return cache["gather_keyspaces_tables"]

@registry.register_check("cassandra")
def keyspaces_customer_managed_encryption(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.1] Amazon Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys"""
    keyspaces = session.client("keyspaces")
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in gather_keyspaces_tables(cache, session):
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        try:
            t = keyspaces.get_table(
                keyspaceName=keyspaceName,
                tableName=tableName
            )
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(t,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Parse details
            resourceArn = t["resourceArn"]

            # This is a failing check
            if t["encryptionSpecification"]["type"] != "CUSTOMER_MANAGED_KMS_KEY":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{resourceArn}/table-cmk-encryption",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
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
                    "Title": "[Keyspaces.1] Amazon Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is not encrypted with a customer-managed key (AWS KMS CMK). Without using CMKs, additional identity-based controls to the table cannot be used to enforce encryption. If this configuration is not intended refer to the remediation guide linked below.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table should be encrypted with a KMS CMK refer to the Encryption at rest in Amazon Keyspaces section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
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
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{resourceArn}/table-cmk-encryption",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
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
                    "Title": "[Keyspaces.1] Amazon Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is encrypted with a customer-managed key (AWS KMS CMK).",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table should be encrypted with a KMS CMK refer to the Encryption at rest in Amazon Keyspaces section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
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
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
        except botocore.exceptions.ValidationException:
            continue

@registry.register_check("cassandra")
def keyspaces_inaccessible_status_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.2] Amazon Keyspaces (Cassandra) Tables should not be in an inaccessible state"""
    keyspaces = session.client("keyspaces")
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in gather_keyspaces_tables(cache, session):
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        try:
            t = keyspaces.get_table(
                keyspaceName=keyspaceName,
                tableName=tableName
            )
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(t,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Parse details
            resourceArn = t["resourceArn"]

            # This is a failing check
            if t["status"] == "INACCESSIBLE_ENCRYPTION_CREDENTIALS":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{resourceArn}/table-inaccessible-encryption-state",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Denial of Service",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "HIGH"},
                    "Confidence": 99,
                    "Title": "[Keyspaces.2] Amazon Keyspaces (Cassandra) Tables should not be in an inaccessible state",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is in an inaccessible state due to encryption credentials. When using KMS CMKs and assigning Key Policies, if you do not provide IAM principals in you AWS Account proper decryption permissions you can lock yourself out of a table. If this configuration is not intended refer to the remediation guide linked below.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table is in an inaccessible state refer to the Troubleshooting Amazon Keyspaces identity and access section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/security_iam_troubleshoot.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST CSF V1.1 DE.AE-5",
                            "NIST CSF V1.1 DE.CM-1",
                            "NIST CSF V1.1 DE.DP-2",                        
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-6",
                            "AICPA TSC CC4.1",
                            "AICPA TSC CC5.1",
                            "ISO 27001:2013 A.10.1.2",
                            "ISO 27001:2013 A.12.4.1"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{resourceArn}/table-inaccessible-encryption-state",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": [
                        "Software and Configuration Checks/AWS Security Best Practices",
                        "Effects/Denial of Service",
                    ],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Keyspaces.2] Amazon Keyspaces (Cassandra) Tables should not be in an inaccessible state",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is not in an inaccessible state due to encryption credentials.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table is in an inaccessible state refer to the Troubleshooting Amazon Keyspaces identity and access section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/security_iam_troubleshoot.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 DE.AE-2",
                            "NIST CSF V1.1 DE.AE-3",
                            "NIST CSF V1.1 DE.AE-5",
                            "NIST CSF V1.1 DE.CM-1",
                            "NIST CSF V1.1 DE.DP-2",                        
                            "NIST SP 800-53 Rev. 4 AC-2",
                            "NIST SP 800-53 Rev. 4 AU-6",
                            "NIST SP 800-53 Rev. 4 AU-12",
                            "NIST SP 800-53 Rev. 4 IR-5",
                            "NIST SP 800-53 Rev. 4 IR-6",
                            "AICPA TSC CC4.1",
                            "AICPA TSC CC5.1",
                            "ISO 27001:2013 A.10.1.2",
                            "ISO 27001:2013 A.12.4.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
        except botocore.exceptions.ValidationException:
            continue

@registry.register_check("cassandra")
def keyspaces_pitr_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.3] Amazon Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled"""
    keyspaces = session.client("keyspaces")
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in gather_keyspaces_tables(cache, session):
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        try:
            t = keyspaces.get_table(
                keyspaceName=keyspaceName,
                tableName=tableName
            )
            # B64 encode all of the details for the Asset
            assetJson = json.dumps(t,default=str).encode("utf-8")
            assetB64 = base64.b64encode(assetJson)
            # Parse details
            resourceArn = t["resourceArn"]

            # This is a failing check
            if t["pointInTimeRecovery"]["status"] == "DISABLED":
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{resourceArn}/table-pitr-enabled",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "LOW"},
                    "Confidence": 99,
                    "Title": "[Keyspaces.3] Amazon Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} does not have Point-in-Time Recovery (PITR) enabled. PITR helps protect your Amazon Keyspaces tables from accidental write or delete operations by providing you continuous backups of your table data. If this configuration is not intended refer to the remediation guide linked below.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table should have PITR enabled refer to the Point-in-time recovery for Amazon Keyspaces (for Apache Cassandra) section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/PointInTimeRecovery.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.BE-5", 
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 SA-13",
                            "NIST SP 800-53 Rev. 4 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
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
                    "Id": f"{resourceArn}/table-pitr-enabled",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": resourceArn,
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[Keyspaces.3] Amazon Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled",
                    "Description": f"Amazon Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} has Point-in-Time Recovery (PITR) enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your Cassandra table should have PITR enabled refer to the Point-in-time recovery for Amazon Keyspaces (for Apache Cassandra) section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                            "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/PointInTimeRecovery.html",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "AWS",
                        "ProviderType": "CSP",
                        "ProviderAccountId": awsAccountId,
                        "AssetRegion": awsRegion,
                        "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Amazon Keyspaces",
                        "AssetComponent": "Table"
                    },
                    "Resources": [
                        {
                            "Type": "AwsKeyspacesTable",
                            "Id": resourceArn,
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "KeyspaceName": keyspaceName, 
                                    "TableName": tableName
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 ID.BE-5", 
                            "NIST CSF V1.1 PR.PT-5",
                            "NIST SP 800-53 Rev. 4 CP-2",
                            "NIST SP 800-53 Rev. 4 CP-11",
                            "NIST SP 800-53 Rev. 4 SA-13",
                            "NIST SP 800-53 Rev. 4 SA14",
                            "AICPA TSC CC3.1",
                            "AICPA TSC A1.2",
                            "ISO 27001:2013 A.11.1.4",
                            "ISO 27001:2013 A.17.1.1",
                            "ISO 27001:2013 A.17.1.2",
                            "ISO 27001:2013 A.17.2.1"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                continue
        except botocore.exceptions.ValidationException:
            continue