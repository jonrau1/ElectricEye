from check_register import CheckRegister
import boto3
import datetime

registry = CheckRegister()

keyspaces = boto3.client("keyspaces")

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
keyspace_paginator = keyspaces.get_paginator("list_keyspaces")
table_paginator = keyspaces.get_paginator("list_tables")
keyspace_iterator = keyspace_paginator.paginate()
for page in keyspace_iterator:
    for k in page["keyspaces"]:
        keyspaceName = k["keyspaceName"]
        if keyspaceName in defaultKeyspaceNames:
            continue
        else:
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

del keyspace_iterator
del keyspace_paginator
del table_iterator
del table_paginator

if not awsKeyspaceInfo:
    # If there is an empty list no need to attempt anything else
    pass

@registry.register_check("keyspaces")
def keyspaces_customer_managed_encryption(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.1] AWS Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys"""
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in awsKeyspaceInfo:
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        t = keyspaces.get_table(
            keyspaceName=keyspaceName,
            tableName=tableName
        )
        # Parse details
        resourceArn = t["resourceArn"]

        # This is a failing check
        if t["encryptionSpecification"]["type"] != "CUSTOMER_MANAGED_KMS_KEY":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": resourceArn + "/table-cmk-encryption",
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
                "Title": "[Keyspaces.1] AWS Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is not encrypted with a customer-managed key (AWS KMS CMK). Without using CMKs, additional identity-based controls to the table cannot be used to enforce encryption. If this configuration is not intended refer to the remediation guide linked below.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table should be encrypted with a KMS CMK refer to the Encryption at rest in Amazon Keyspaces section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": resourceArn + "/table-cmk-encryption",
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
                "Title": "[Keyspaces.1] AWS Keyspaces (Cassandra) Tables should be encrypted with customer-managed keys",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is encrypted with a customer-managed key (AWS KMS CMK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table should be encrypted with a KMS CMK refer to the Encryption at rest in Amazon Keyspaces section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
                        "NIST CSF PR.DS-1",
                        "NIST SP 800-53 MP-8",
                        "NIST SP 800-53 SC-12",
                        "NIST SP 800-53 SC-28",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                    ],
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("keyspaces")
def keyspaces_inaccessible_status_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.2] AWS Keyspaces (Cassandra) Tables should not be in an inaccessible state"""
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in awsKeyspaceInfo:
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        t = keyspaces.get_table(
            keyspaceName=keyspaceName,
            tableName=tableName
        )
        # Parse details
        resourceArn = t["resourceArn"]

        # This is a failing check
        if t["status"] == "INACCESSIBLE_ENCRYPTION_CREDENTIALS":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": resourceArn + "/table-inaccessible-encryption-state",
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
                "Title": "[Keyspaces.2] AWS Keyspaces (Cassandra) Tables should not be in an inaccessible state",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is in an inaccessible state due to encryption credentials. When using KMS CMKs and assigning Key Policies, if you do not provide IAM principals in you AWS Account proper decryption permissions you can lock yourself out of a table. If this configuration is not intended refer to the remediation guide linked below.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table is in an inaccessible state refer to the Troubleshooting Amazon Keyspaces identity and access section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/security_iam_troubleshoot.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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
                "Id": resourceArn + "/table-inaccessible-encryption-state",
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
                "Title": "[Keyspaces.2] AWS Keyspaces (Cassandra) Tables should not be in an inaccessible state",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} is not in an inaccessible state due to encryption credentials.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table is in an inaccessible state refer to the Troubleshooting Amazon Keyspaces identity and access section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/security_iam_troubleshoot.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
                        "NIST CSF DE.AE-2",
                        "NIST CSF DE.AE-3",
                        "NIST CSF DE.AE-5",
                        "NIST CSF DE.CM-1",
                        "NIST CSF DE.DP-2",                        
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 IR-5",
                        "NIST SP 800-53 IR-6",
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

@registry.register_check("keyspaces")
def keyspaces_pitr_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Keyspaces.3] AWS Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled"""
    # ISO8061 Timestamp
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # Grab table information from saved dict in script
    for x in awsKeyspaceInfo:
        keyspaceName = x["KeyspaceName"]
        tableName = x["TableName"]
        # Retrieve information from `get_table()` API
        t = keyspaces.get_table(
            keyspaceName=keyspaceName,
            tableName=tableName
        )
        # Parse details
        resourceArn = t["resourceArn"]

        # This is a failing check
        if t["pointInTimeRecovery"]["status"] == "DISABLED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": resourceArn + "/table-pitr-enabled",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": resourceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Keyspaces.3] AWS Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} does not have Point-in-Time Recovery (PITR) enabled. PITR helps protect your Amazon Keyspaces tables from accidental write or delete operations by providing you continuous backups of your table data. If this configuration is not intended refer to the remediation guide linked below.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table should have PITR enabled refer to the Point-in-time recovery for Amazon Keyspaces (for Apache Cassandra) section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/PointInTimeRecovery.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
                        "NIST CSF ID.BE-5", 
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
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
                "Id": resourceArn + "/table-pitr-enabled",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": resourceArn,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Keyspaces.3] AWS Keyspaces (Cassandra) Tables should have Point-in-Time Recovery (PITR) enabled",
                "Description": f"AWS Keyspaces for Cassandra table {tableName} in Keyspace {keyspaceName} has Point-in-Time Recovery (PITR) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your Cassandra table should have PITR enabled refer to the Point-in-time recovery for Amazon Keyspaces (for Apache Cassandra) section of the Amazon Keyspaces (for Apache Cassandra) Developer Guide",
                        "Url": "https://docs.aws.amazon.com/keyspaces/latest/devguide/PointInTimeRecovery.html",
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCassandraTable",
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
                        "NIST CSF ID.BE-5", 
                        "NIST CSF PR.PT-5",
                        "NIST SP 800-53 CP-2",
                        "NIST SP 800-53 CP-11",
                        "NIST SP 800-53 SA-13",
                        "NIST SP 800-53 SA14",
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