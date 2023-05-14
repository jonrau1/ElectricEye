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
        # We actually get back some schema which is immediately useful - so append away my guy
        aHugeBoxOfAutonomousDatabases.append(
            process_response(
                dbClient.list_autonomous_databases(
                    compartment_id=compartment
                ).data
            )
        )

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
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the About Master Encryption Key Management on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
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
                        "Text": "For more information on using a customer-managed MEK for your file system refer to the About Master Encryption Key Management on Autonomous Database section of the Oracle Cloud Infrastructure Documentation for Autonomous Databases.",
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

# [OCI.AutonomousDatabase.2] Available Upgrade Target - if autodb["available_upgrade_versions"]

# [OCI.AutonomousDatabase.3] Manual Backup should be configured - if autodb["backup_config"]["manual_backup_bucket_name"] is None

# [OCI.AutonomousDatabase.4] Registered with Oracle Data Safe - if autodb["data_safe_status"] != "REGISTERED"

# [OCI.AutonomousDatabase.5] Registered with Database Management - if autodb["database_management_status"] is None

# [OCI.AutonomousDatabase.6] Access Controls should be enabled - if autodb["is_access_control_enabled"] is None

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