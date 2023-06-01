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

def get_nosql_tables(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    
    response = cache.get("get_nosql_tables")
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

    nosqlClient = oci.nosql.NosqlClient(config)

    aListOfDictsOfNoSqlTables = []

    for compartment in ociCompartments:
        listTables = nosqlClient.list_tables(compartment_id=compartment)
        for table in process_response(listTables.data)["items"]:
            aListOfDictsOfNoSqlTables.append(table)

    cache["get_nosql_tables"] = aListOfDictsOfNoSqlTables
    return cache["get_nosql_tables"]

@registry.register_check("oci.nosql")
def oci_nosql_db_service_table_on_demand_scaling_check(cache, awsAccountId, awsRegion, awsPartition, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
    """
    [OCI.NoSQL.1] Oracle NoSQL Database Cloud Service tables should be configured for on-demand scaling (autoscaling)
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for table in get_nosql_tables(cache, ociTenancyId, ociUserId, ociRegionName, ociCompartments, ociUserApiKeyFingerprint):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(table,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        compartmentId = table["compartment_id"]
        tableId = table["id"]
        tableName = table["name"]
        lifecycleState = table["lifecycle_state"]
        createdAt = str(table["time_created"])

        if table["table_limits"]["capacity_mode"] != "ON_DEMAND":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{tableId}/oci-nosql-dbs-on-demand-table-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{tableId}/oci-nosql-dbs-on-demand-table-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[OCI.NoSQL.1] Oracle NoSQL Database Cloud Service tables should be configured for on-demand scaling (autoscaling)",
                "Description": f"Oracle NoSQL Database Cloud Service table {tableName} in Compartment {compartmentId} in {ociRegionName} is not configured for on-demand scaling (autoscaling). Oracle NoSQL Database Cloud Service scales to meet application throughput performance requirements with low and predictable latency. As workloads increase with periodic business fluctuations, applications can increase their provisioned throughput to maintain a consistent user experience. As workloads decrease, the same applications can reduce their provisioned throughput, resulting in lower operating expenses. The same holds true for storage requirements. Those can be adjusted based on business fluctuations. With on-demand capacity, you don't need to provision the read or write capacities for each table. You only pay for the read and write units that are actually consumed. Oracle NoSQL Database Cloud Service automatically manages the read and write capacities to meet the needs of dynamic workloads. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying your table refer to the Creating Tables and Indexes section of the Oracle Cloud Infrastructure Documentation for Oracle NoSQL Database Cloud Service.",
                        "Url": "https://docs.oracle.com/en-us/iaas/nosql-database/doc/creating-tables-and-indexes.html#GUID-4382BC75-5448-440E-B9DF-13E6FEC764C1",
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
                    "AssetService": "Oracle NoSQL Database Cloud Service",
                    "AssetComponent": "Table"
                },
                "Resources": [
                    {
                        "Type": "OciNosqlDatabaseCloudServiceTable",
                        "Id": tableId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": tableName,
                                "Id": tableId,
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
                "Id": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{tableId}/oci-nosql-dbs-on-demand-table-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{ociTenancyId}/{ociRegionName}/{compartmentId}/{tableId}/oci-nosql-dbs-on-demand-table-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[OCI.NoSQL.1] Oracle NoSQL Database Cloud Service tables should be configured for on-demand scaling (autoscaling)",
                "Description": f"Oracle NoSQL Database Cloud Service table {tableName} in Compartment {compartmentId} in {ociRegionName} is configured for on-demand scaling (autoscaling).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on modifying your table refer to the Creating Tables and Indexes section of the Oracle Cloud Infrastructure Documentation for Oracle NoSQL Database Cloud Service.",
                        "Url": "https://docs.oracle.com/en-us/iaas/nosql-database/doc/creating-tables-and-indexes.html#GUID-4382BC75-5448-440E-B9DF-13E6FEC764C1",
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
                    "AssetService": "Oracle NoSQL Database Cloud Service",
                    "AssetComponent": "Table"
                },
                "Resources": [
                    {
                        "Type": "OciNosqlDatabaseCloudServiceTable",
                        "Id": tableId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenancyId": ociTenancyId,
                                "CompartmentId": compartmentId,
                                "Region": ociRegionName,
                                "Name": tableName,
                                "Id": tableId,
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