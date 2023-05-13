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

import os
import oci
from oci.config import validate_config
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def process_response(responseObject):
    """
    Receives an OCI Python SDK `Response` type (differs by service) and returns a JSON object
    """

    payload = json.loads(
        str(
            responseObject
        )
    )

    return payload

def get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_mysql_db_systems")
    if response:
        return response

    # Create & Validate OCI Creds - do this after cache check to avoid doing it a lot
    config = {
        "tenancy": ociTenancyId,
        "user": ociUserId,
        "region": ociRegionName,
        "fingerprint": ociUserApiKeyFingerprint,
        "key_file": os.environ["OCI_PEM_FILE_PATH"],
        
    }
    validate_config(config)

    mysqlDbsClient = oci.mysql.DbSystemClient(config)

    mysqlDbSystems = []

    for compartment in ociCompartments:
        for mysqldb in mysqlDbsClient.list_db_systems(compartment_id=compartment, lifecycle_state="ACTIVE").data:
            mysqlDbSystems.append(
                process_response(
                    mysqldb
                )
            )

    cache["get_mysql_db_systems"] = mysqlDbSystems
    return cache["get_mysql_db_systems"]

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_automatic_backups_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.1] MySQL Database Systems should be configured to take automatic backups
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["backup_policy"]["is_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-auto-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-auto-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.1] MySQL Database Systems should be configured to take automatic backups",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is not configured to take automatic backups. MySQL Database Service supports full and incremental backup types. These backups can be created manually, automatically, when you delete a DB system, or by an operator. You can use restore these backups to a new DB system. For data recovery purposes, there is no functional difference between an incremental backup and a full backup. You can restore data from any of your incremental or full backups. Both backup types enable you to restore full data to the point-in-time when the backup was taken. An Automatic backup is created automatically at a time selected while creating the DB system. The default retention period is 7 days. You can define the retention period between 1 and 35 days. The automatic backup schedule backs up an inactive DB system too. When you delete a DB system, the automatic backups are deleted too. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Database System automatic backups refer to the Overview of Backups section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/overview-backups.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-auto-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-auto-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.1] MySQL Database Systems should be configured to take automatic backups",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is configured to take automatic backups.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Database System automatic backups refer to the Overview of Backups section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/overview-backups.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_pitr_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.2] MySQL Database Systems should have Point-in-Time Recovery (PITR) enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["backup_policy"]["pitr_policy"]["is_enabled"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-pitr-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-pitr-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.1] MySQL Database Systems should be configured to take automatic backups",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does not have Point-in-Time Recovery (PITR) enabled. You can restore data from a DB system to a new DB system at the latest available point-in-time or a specific point-in-time. Point-in-time recovery provides a Recovery Point Objective (RPO) of approximately five minutes while the daily backup provides you a RPO of 24 hours. When you enable point-in-time recovery, MySQL Database Service takes an initial full backup (Backup type: Full, Creation Type: automatic). Later on, the backups are incremental backups. You can restore to any specific point-in-time within the earliest and the latest time window. The earliest and the latest time window is displayed in the Console under the Select a specific point-in-time option. The earliest available time depends on the backup retention period. For example, if you set the backup retention period to 12 days, the earliest available time is 12 days. Under most circumstances, you cannot restore a PITR snapshot onto a different system target, for instance you cannot use a single-instance standalone Database System PITR to start a HA configured Database System. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Point In Time Recovery refer to the Point-In-Time Recovery section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/point-time-recovery.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-pitr-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-pitr-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.1] MySQL Database Systems should be configured to take automatic backups",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does have Point-in-Time Recovery (PITR) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Point In Time Recovery refer to the Point-In-Time Recovery section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/point-time-recovery.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_crash_recovery_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.3] MySQL Database Systems should have Crash Recovery enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["crash_recovery"] != "ENABLED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-crash-recovery-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-crash-recovery-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.3] MySQL Database Systems should have Crash Recovery enabled",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does not have Crash Recovery enabled. If you enable crash recovery on the DB system, it protects the DB system against data loss in the event of an unexpected server exit. You can disable it to increase the performance of large data imports. Disabling Crash Recovery disables automatic backups. MySQL Server supports crash recovery, which ensures durability and enables data recovery in the event of an unexpected server exit. While this redundancy is advantageous during normal operation of the server, it can lower the performance of large data imports. You can disable the crash recovery processes, temporarily, enabling you to execute DML statements without the overhead of synchronization. If any component of a standalone DB system fails while crash recovery is disabled, the DB system enters a FAILED state and is unrecoverable. It is recommended to perform a full manual backup before disabling crash recovery. Highly available DB systems in multi-availability domains are more failure resistant but in certain circumstances, can also become unrecoverable. Disabling crash recovery disables: InnoDB redo log, Doublewrite buffer and Binary log synchronization. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Crash Recovery and fail planning with Crash Recovery refer to the Crash Recovery section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/mysql-server.html#GUID-19A6771C-E517-4121-8D7E-ECE59ED2AF9E",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-crash-recovery-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-crash-recovery-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.3] MySQL Database Systems should have Crash Recovery enabled",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does have Crash Recovery enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on configuring Crash Recovery and fail planning with Crash Recovery refer to the Crash Recovery section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/mysql-server.html#GUID-19A6771C-E517-4121-8D7E-ECE59ED2AF9E",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_deletion_protection_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.4] MySQL Database Systems should have Deletion Protection enabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["deletion_policy"]["is_delete_protected"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-deletion-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.4] MySQL Database Systems should have Deletion Protection enabled",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does not have Deletion Protection enabled. The Delete Protected option protects your DB system against delete operations. To enable you to delete your DB system, disable the option. By default, DB systems are not delete protected. Remember, GitLab failed for over 18 hours because someone deleted the wrong production database - deletion protection helps prevent accidently or maliciously deleting a database and should be combined with other recovery retention and deletion plan options to promote resilience and recovery of your databases. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-deletion-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.4] MySQL Database Systems should have Deletion Protection enabled",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does have Deletion Protection enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_final_snapshot_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.5] MySQL Database Systems should enforce creating a final manual snapshot before deletion
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["deletion_policy"]["final_backup"] != "REQUIRE_FINAL_BACKUP":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-final-snapshot-on-delete-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-final-snapshot-on-delete-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.5] MySQL Database Systems should enforce creating a final manual snapshot before deletion",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does not enforce creating a final manual snapshot before deletion. The Require final backup setting creates a final backup before deleting the DB system. By default, the final backup is not created. In the event that your Database System is not Deletion Protected, this helps maintain a Recovery Point Objective (RPO) of up to the amount of time the final backup is retained if the deletion was accidental or malicious. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-final-snapshot-on-delete-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-final-snapshot-on-delete-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.5] MySQL Database Systems should enforce creating a final manual snapshot before deletion",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} does enforce creating a final manual snapshot before deletion.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_delete_auto_snapshots_on_delete_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.6] MySQL Database Systems should be configured to automatically delete automatic snapshots after system deletion
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["deletion_policy"]["automatic_backup_retention"] != "DELETE":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-delete-auto-snapshots-on-delete-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-delete-auto-snapshots-on-delete-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.6] MySQL Database Systems should be configured to automatically delete automatic snapshots after system deletion",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is not configured to automatically delete automatic snapshots after system deletion. The Retain automatic backups option will retain automatic backups after you delete your DB system. By default, automatic backups are deleted when you delete the DB system. Retaining automatic snapshots, depending on their retention and frequency, can increase storage costs. When using this option with other deletion planning options it may be wiser to take a final snapshot and deletion protect your Database Systems for business- and mission-critical workloads. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-delete-auto-snapshots-on-delete-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-delete-auto-snapshots-on-delete-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.6] MySQL Database Systems should be configured to automatically delete automatic snapshots after system deletion",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is configured to automatically delete automatic snapshots after system deletion.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

@registry.register_check("oci.mysqldbs")
def oci_mysql_dbsystem_high_availability_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.MySQLDatabaseService.7] MySQL Database Systems should be configured to be highly available
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for mysqldbs in get_mysql_db_systems(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(mysqldbs,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = mysqldbs["compartment_id"]
        mysqldbsId = mysqldbs["id"]
        mysqldbsName = mysqldbs["display_name"]
        lbLifecycleState = mysqldbs["lifecycle_state"]
        createdAt = str(mysqldbs["time_created"])

        if mysqldbs["is_highly_available"] is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-high-availability-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-high-availability-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.7] MySQL Database Systems should be configured to be highly available",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is not highly available. A high availability DB system is made up of three MySQL instances: a primary instance and two secondary instances. Each MySQL instance utilizes the same amount of block volume storage, number of OCPUs, and amount of RAM defined in the shape chosen. The primary instance functions as a read/write endpoint and you have read/write access to the primary instance only. All data that you write to the primary instance is copied to the secondary instances asynchronously. The secondary instances are placed in different availability or fault domains. High availablility DB systems consume more resources (OCPUs, RAM, network bandwidth) than standalone DB systems. Hence the throughput and latency differ from the standalone DB systems. High availability uses MySQL Group Replication to replicate data from the primary instance to the secondary instances. The replication occurs over a secure, managed, internal network, unconnected to the VCN subnet you configured for the DB system. Limited information about this internal network is available in some Performance Schema tables, and you can neither connect to it nor view any other information related to it. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on High Availability refer to the Overview of High Availability section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/overview-high-availability.html#GUID-0387FC6B-73DF-4447-A206-3CBA2EB0FFB3",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-high-availability-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{mysqldbsId}/oci-mysql-dbs-high-availability-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.MySQLDatabaseService.7] MySQL Database Systems should be configured to be highly available",
                "Description": f"Oracle MySQL Database System {mysqldbsName} in Compartment {compartmentId} in {ociRegionName} is highly available.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Deletion Planning for Database Systems refer to the Advanced Option: Deletion Plan section of the Oracle Cloud Infrastructure Documentation for MySQL Database.",
                        "Url": "https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "OCI",
                    "ProviderType": "CSP",
                    "ProviderAccountId": ociTenancyId,
                    "AssetRegion": ociRegionName,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Oracle MySQL Database Service",
                    "AssetComponent": "Database System"
                },
                "Resources": [
                    {
                        "Type": "OciMySqlDatabaseServiceDatabaseSystem",
                        "Id": mysqldbsId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": mysqldbsName,
                                "Id": mysqldbsId,
                                "CreatedAt": createdAt,
                                "LifecycleState": lbLifecycleState
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
                        "NIST SP 800-53 Rev. 4 SA-14",
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

## END ??