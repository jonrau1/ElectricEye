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

def get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_autonomous_databases")
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

    dbClient = oci.database.DatabaseClient(config)

    aHugeBoxOfAutonomousDatabases = []

    for compartment in ociCompartments:
        for autodb in dbClient.list_autonomous_databases(compartment_id=compartment, lifecycle_state="AVAILABLE").data:
            autodb = process_response(autodb)
            aHugeBoxOfAutonomousDatabases.append(autodb)

    cache["get_autonomous_databases"] = aHugeBoxOfAutonomousDatabases
    return cache["get_autonomous_databases"]

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_cmk_mek_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.1] Autonomous Databases should be encrypted with a Customer-managed Master Encryption Key
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["kms_key_id"] == "ORACLE_MANAGED_KEY":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.1] Autonomous Databases should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does not use a Customer-managed Master Encryption Key. Oracle Autonomous Database uses always-on encryption that protects data at rest and in transit. Data at rest and in motion is encrypted by default. Encryption cannot be turned off. Data at rest is encrypted using TDE (Transparent Data Encryption), a cryptographic solution that protects the processing, transmission, and storage of data. Using AES256 tablespace encryption, each database has its own encryption key, and any backups have their own different encryption keys. By default, Oracle Autonomous Database creates and manages all the master encryption keys used to protect your data, storing them in a secure PKCS 12 keystore on the same systems where the database resides. If your company security policies require, Oracle Autonomous Database can instead use keys you create and manage in the Oracle Cloud Infrastructure Vault service. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your Autonomous Database refer to the About Master Encryption Key Management on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/about-user-managed-key.html#GUID-F7FE0CAD-FE11-46DF-A14C-4A1E56DC5777",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-cmk-mek-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-cmk-mek-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.1] Autonomous Databases should be encrypted with a Customer-managed Master Encryption Key",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does use a Customer-managed Master Encryption Key.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on using a customer-managed MEK for your Autonomous Database refer to the About Master Encryption Key Management on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/about-user-managed-key.html#GUID-F7FE0CAD-FE11-46DF-A14C-4A1E56DC5777",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                        "ISO 27001:2013 A.8.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_available_upgrade_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.2] Autonomous Databases with available upgrade versions should be reviewed for upgrade
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["available_upgrade_versions"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-available-upgrade-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-available-upgrade-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.2] Autonomous Databases with available upgrade versions should be reviewed for upgrade",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} has available upgrade versions. When there is an available upgrade in Oracle Cloud Autonomous Database, you have the option to upgrade your database to the latest version. The available upgrade is usually indicated in the Oracle Cloud Infrastructure Console, and you will receive notifications about the upgrade. Before upgrading your database, you should review the documentation and release notes for the new version to ensure that the upgrade does not affect your applications or databases in unexpected ways. Once you are ready to upgrade, you can initiate the upgrade process through the Oracle Cloud Infrastructure Console or by using the Oracle Cloud Infrastructure CLI or SDK. The upgrade process will typically involve creating a new database deployment with the new version, migrating your data to the new deployment, and then switching your applications to the new database. The actual steps and process may vary depending on your specific database and application configuration. Keeping up-to-date with upgrade versions are typically dictate by application or IT teams, however, upgrades can contain important security enhancements or patches and should be reviewed. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on patching, maintainance windows, and upgrading your Autonomous Database refer to the View Patch and Maintenance Window Information, Set the Patch Level section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/maintenance-windows-patching.html#GUID-C4F488BA-C2ED-4890-A411-9F99C69CD8DF",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-available-upgrade-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-available-upgrade-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.2] Autonomous Databases with available upgrade versions should be reviewed for upgrade",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does not have available upgrade versions.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on patching, maintainance windows, and upgrading your Autonomous Database refer to the View Patch and Maintenance Window Information, Set the Patch Level section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/maintenance-windows-patching.html#GUID-C4F488BA-C2ED-4890-A411-9F99C69CD8DF",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_manual_backup_bucket_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.3] Autonomous Databases should have an Oracle Object Storage bucket configured for manual and long-term backup storage
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["backup_config"]["manual_backup_bucket_name"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-long-backup-bucket-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-long-backup-bucket-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.3] Autonomous Databases should have an Oracle Object Storage bucket configured for manual and long-term backup storage",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does not have an Oracle Object Storage bucket configured for manual and long-term backup storage. Regarding Files on Object Store, for external tables, partitioned external tables, and the external partitions of hybrid partitioned tables, backups do not include the external files that reside on Object Store. Thus, for operations where you use a backup to restore your database, such as Restore or Clone from a backup, it is your responsibility to backup and restore if necessary, the external files associated with external tables, external partitioned tables, or the external files for a hybrid partitioned table. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on long term backups and using Object Storage for your Autonomous Database refer to the Backup and Restore Notes section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/backup-restore-notes.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-long-backup-bucket-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-long-backup-bucket-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.3] Autonomous Databases should have an Oracle Object Storage bucket configured for manual and long-term backup storage",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does have an Oracle Object Storage bucket configured for manual and long-term backup storage.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on long term backups and using Object Storage for your Autonomous Database refer to the Backup and Restore Notes section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en-us/iaas/autonomous-database-shared/doc/backup-restore-notes.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
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

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_data_safe_registered_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.4] Autonomous Databases should be registered with Oracle Data Safe
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["data_safe_status"] != "REGISTERED":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-data-safe-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-data-safe-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.4] Autonomous Databases should be registered with Oracle Data Safe",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} is not registered with Oracle Data Safe. Oracle Data Safe is a unified control center for your Oracle databases which helps you understand the sensitivity of your data, evaluate risks to data, mask sensitive data, implement and monitor security controls, assess user security, monitor user activity, and address data security compliance requirements. Use Oracle Data Safe to apply auditing policies for database users, for administrative users, to apply predefined auditing policies or to extend the audit data record retention for your Autonomous Database. Oracle Data Safe is a very important safeguard especially if your Autonomous Database will be handling any sensitive, classified, or otherwise controlled data for mission or business needs. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on registering your Autonomous Database refer to the Enable and Register Oracle Data Safe on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/adb-audit-enable-data-safe.html#GUID-C99570AD-0DC2-415E-AF60-734AC60B4AAB",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC 7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-data-safe-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-data-safe-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.4] Autonomous Databases should be registered with Oracle Data Safe",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} is registered with Oracle Data Safe.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on registering your Autonomous Database refer to the Enable and Register Oracle Data Safe on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/adb-audit-enable-data-safe.html#GUID-C99570AD-0DC2-415E-AF60-734AC60B4AAB",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC 7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_db_management_registered_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.5] Autonomous Databases should be registered with Database Management
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["database_management_status"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-database-management-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-database-management-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.5] Autonomous Databases should be registered with Database Management",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} is not registered with Database Management. Database management provides comprehensive database performance diagnostics and management capabilities to monitor and manage Oracle Databases. You can use Database Management to monitor a single Autonomous Database or a fleet of Autonomous Databases and obtain meaningful insights from the metrics pushed to the Oracle Cloud Infrastructure Monitoring service. On enabling Database Management for Autonomous Databases, you can perform the following Database Management tasks at an additional cost: Monitor the health of your fleet of Autonomous Databases, Monitor a single Autonomous Database on the Managed database details page and/or Group Autonomous Databases that reside across compartments into a Database Group, and monitor them. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on registering your Autonomous Database refer to the About Database Management for Autonomous Databases section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/iaas/database-management/doc/database-management-autonomous-databases.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-database-management-registered-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-database-management-registered-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.5] Autonomous Databases should be registered with Database Management",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} is registered with Database Management.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on registering your Autonomous Database refer to the About Database Management for Autonomous Databases section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/iaas/database-management/doc/database-management-autonomous-databases.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("oci.autonomousdatabase")
def oci_autodb_customer_contact_provided_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.AutonomousDatabase.6] Autonomous Databases should have a customer contact detail to receive upgrade and other important notices
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for autodb in get_autonomous_databases(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(autodb,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = autodb["compartment_id"]
        autodbId = autodb["id"]
        autodbName = autodb["display_name"]
        lifecycleState = autodb["lifecycle_state"]
        createdAt = str(autodb["time_created"])

        if autodb["customer_contacts"] is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-customer-contact-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-customer-contact-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.6] Autonomous Databases should have a customer contact detail to receive upgrade and other important notices",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does not have a customer contact detail to receive upgrade and other important notices. When customer contacts are set, Oracle sends notifications to the specified email addresses for Autonomous Database service-related issues. Contacts in the customer contacts list receive unplanned maintenance notices and other notices, including but not limited to notices for database upgrades and upcoming wallet expiration. When customer contacts are not set the notifications go to the tenancy admin email address associated with the account. Oracle recommends that you set the customer contacts so that the appropriate people receive service-related notifications. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on adding customer contacts to your Autonomous Database refer to the View and Manage Customer Contacts for Operational Issues and Announcements section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/customer-contacts.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-customer-contact-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{autodbId}/oci-autodb-customer-contact-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.AutonomousDatabase.6] Autonomous Databases should have a customer contact detail to receive upgrade and other important notices",
                "Description": f"Oracle Autonomous Database {autodbName} in Compartment {compartmentId} in {ociRegionName} does have a customer contact detail to receive upgrade and other important notices.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on adding customer contacts to your Autonomous Database refer to the View and Manage Customer Contacts for Operational Issues and Announcements section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
                        "Url": "https://docs.oracle.com/en/cloud/paas/autonomous-database/adbsa/customer-contacts.html",
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
                    "AssetService": "Oracle Autonomous Database",
                    "AssetComponent": "Database"
                },
                "Resources": [
                    {
                        "Type": "OciAutonomousDatabaseDatabase",
                        "Id": autodbId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": autodbName,
                                "Id": autodbId,
                                "LifecycleState": lifecycleState,
                                "CreatedAt": createdAt
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.MA-1",
                        "NIST SP 800-53 Rev. 4 MA-2",
                        "NIST SP 800-53 Rev. 4 MA-3",
                        "NIST SP 800-53 Rev. 4 MA-5",
                        "NIST SP 800-53 Rev. 4 MA-6",
                        "AICPA TSC CC8.1",
                        "ISO 27001:2013 A.11.1.2",
                        "ISO 27001:2013 A.11.2.4",
                        "ISO 27001:2013 A.11.2.5",
                        "ISO 27001:2013 A.11.2.6"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# [OCI.AutonomousDatabase.7] Database resource autoscaling - if autodb["is_auto_scaling_enabled"] is False

# [OCI.AutonomousDatabase.8] Database storage autoscaling - if autodb["is_auto_scaling_for_storage_enabled"] is False

# [OCI.AutonomousDatabase.9] Is Oracle Data Guard enabled - if autodb["is_data_guard_enabled"] is False

# [OCI.AutonomousDatabase.10] is mutual TLS (mTLS) access enforced - if autodb["is_mtls_connection_required"] is False

# [OCI.AutonomousDatabase.11] Are long term backups scheduled - if autodb["long_term_backup_schedule"] is None

# [OCI.AutonomousDatabase.12] Using NSGs - if autodb["nsg_ids"] is None

# [OCI.AutonomousDatabase.13] Ops Insights enabled - if autodb["operations_insights_status"] == "NOT_ENABLED"

# [OCI.AutonomousDatabase.14] Permissions Level (admin access only to DB, this doesn't really matter) - if autodb["permission_level"] == "UNRESTRICTED"

# [OCI.AutonomousDatabase.15] Private Endpoint Access Only - if autodb["private_endpoint"] is None

# [OCI.AutonomousDatabase.16] IP Allowlisting - if not autodb["whitelisted_ips"] or if "0.0.0.0/0" in autodb["whitelisted_ips"]

## END ??