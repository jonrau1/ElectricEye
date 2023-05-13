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

# Automatic Backups Enabled - https://docs.oracle.com/en-us/iaas/mysql-database/doc/overview-backups.html
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

# PITR Enabled - https://docs.oracle.com/en-us/iaas/mysql-database/doc/point-time-recovery.html

# Crash Recovery Enabled - https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-72E2E499-8EA5-48C1-AF1E-F8FF98D4F115

# Deletion Protection  - https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-72E2E499-8EA5-48C1-AF1E-F8FF98D4F115

# Final Backup Required - https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85

# Automatic Backup Retention Deletion (avoid incurring costs) - https://docs.oracle.com/en-us/iaas/mysql-database/doc/advanced-options.html#MYAAS-GUID-29A995D2-1D40-4AE8-A654-FB6F40B07D85

# Is Highly Available - https://docs.oracle.com/en-us/iaas/mysql-database/doc/overview-high-availability.html#GUID-0387FC6B-73DF-4447-A206-3CBA2EB0FFB3