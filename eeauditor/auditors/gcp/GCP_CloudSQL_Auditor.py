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
from check_register import CheckRegister
import googleapiclient.discovery
import base64
import json

registry = CheckRegister()

def get_cloudsql_dbs(cache, gcpProjectId):
    """
    AggregatedList result provides Zone information as well as every single Instance in a Project
    """
    response = cache.get("get_cloudsql_dbs")
    if response:
        return response

    # CloudSQL requires SQL Admin API - also doesnt need an aggregatedList
    service = googleapiclient.discovery.build('sqladmin', 'v1beta4')
    instances = service.instances().list(project=gcpProjectId).execute()

    if instances:
        cache["get_cloudsql_dbs"] = instances["items"]
        return cache["get_cloudsql_dbs"]
    else:
        return {}

@registry.register_check("cloudsql")
def cloudsql_instance_public_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # If this value is True, it means a Public IP is assigned
        if csql["settings"]["ipConfiguration"]["ipv4Enabled"] == True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-public-instance-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-public-instance-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable",
                "Description": f"CloudSQL instance {name} in {zone} is publicly reachable due to an external IP assignment. While not inherently dangerous as this check does not take into account any additional security controls, databases should only be available to private IP address space and use minimalistic VPC Firewall Rules along with strong authentication. Publicly reachable databases without complentary security controls may leave your database resource and the data therein susceptible to destruction, manipulation, and/or capture by adversaries and unauthorized personnel. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should not have a public IP assigned refer to the Configure public IP section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/configure-ip",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding 
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-public-instance-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-public-instance-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.1] CloudSQL Instances should not be publicly reachable",
                "Description": f"CloudSQL instance {name} in {zone} is not publicly reachable due to not having an external IP assignment.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should not have a public IP assigned refer to the Configure public IP section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/configure-ip",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST CSF V1.1 PR.AC-4",
                        "NIST CSF V1.1 PR.DS-5",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AC-5",
                        "NIST SP 800-53 Rev. 4 AC-6",
                        "NIST SP 800-53 Rev. 4 AC-14",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 PE-19",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "NIST SP 800-53 Rev. 4 PS-6",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-13",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "NIST SP 800-53 Rev. 4 SC-31",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC6.3",
                        "AICPA TSC CC6.6",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.6.1.2",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.7.1.2",
                        "ISO 27001:2013 A.7.3.1",
                        "ISO 27001:2013 A.8.2.2",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.9.1.1",
                        "ISO 27001:2013 A.9.1.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.4.1",
                        "ISO 27001:2013 A.9.4.4",
                        "ISO 27001:2013 A.9.4.5",
                        "ISO 27001:2013 A.10.1.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.11.1.5",
                        "ISO 27001:2013 A.11.2.1",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.1.3",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.13.2.4",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_standard_backup_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.2] CloudSQL Instances should have automated backups configured
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # Check if basic backups are enabled - this is a failing check
        if csql["settings"]["backupConfiguration"]["enabled"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-basic-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-basic-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.2] CloudSQL Instances should have automated backups configured",
                "Description": f"CloudSQL instance {name} in {zone} does not have backups enabled. Automated backups are used to restore a Cloud SQL instance, and provide a way to recover data in the event of a disaster, such as hardware failure, human error, or a natural disaster or protect against data loss by providing a copy of the data that can be restored if the original data is lost or corrupted. Cloud SQL backups can be automated and managed through the GCP console or API, simplifying the process of creating and managing backups. Cloud SQL backups are stored in a separate location, which can help reduce the risk of data loss due to regional outages or disasters. Additionally, backups can be configured to fit the needs of the organization, helping to reduce unnecessary costs. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have backups enabled refer to the Automated backup and transaction log retention section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups#retention",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-basic-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-basic-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.2] CloudSQL Instances should have automated backups configured",
                "Description": f"CloudSQL instance {name} in {zone} has automated backups enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have backups enabled refer to the Automated backup and transaction log retention section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups#retention",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding 

@registry.register_check("cloudsql")
def cloudsql_instance_mysql_pitr_backup_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.3] CloudSQL MySQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        # Check if the DB engine (to use an AWS term, lol) matches what we want
        # example output is MYSQL_8_0_26 or POSTGRES_14
        dbEngine = databaseVersion.split("_")[0]
        if dbEngine != "MYSQL":
            continue
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # "binaryLogEnabled" only appears for Mysql
        if csql["settings"]["backupConfiguration"]["binaryLogEnabled"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-mysql-pitr-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-mysql-pitr-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.3] CloudSQL MySQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured",
                "Description": f"CloudSQL instance {name} in {zone} does not have point-in-time recovery (PITR) configured. For databases that are part of business- or mission-critical applications or that need to maintain as little data loss as possible, considered enabling PITR. PITR, or Binary Logs for MySQL, allows the restoration of data from a specific point in time, making it easier to recover from data corruption or malicious activities, such as ransomware attacks. This is because PITR provides a way to revert the database to a state before the attack occurred, minimizing the impact of the attack and reducing the amount of data that is lost. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your MYSQL CloudSQL instance should have PITR backups enabled refer to the Use point-in-time recovery section of the GCP MySQL CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/pitr",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-mysql-pitr-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-mysql-pitr-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.3] CloudSQL MySQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured",
                "Description": f"CloudSQL instance {name} in {zone} has point-in-time recovery (PITR) configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your MYSQL CloudSQL instance should have PITR backups enabled refer to the Use point-in-time recovery section of the GCP MySQL CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/backup-recovery/pitr",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_psql_pitr_backup_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.4] CloudSQL PostgreSQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        # Check if the DB engine (to use an AWS term, lol) matches what we want
        # example output is MYSQL_8_0_26 or POSTGRES_14
        dbEngine = databaseVersion.split("_")[0]
        if dbEngine != "POSTGRES":
            continue
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # "pointInTimeRecoveryEnabled" only appears for Psql
        if csql["settings"]["backupConfiguration"]["pointInTimeRecoveryEnabled"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-psql-pitr-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-psql-pitr-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.4] CloudSQL PostgreSQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured",
                "Description": f"CloudSQL instance {name} in {zone} does not have point-in-time recovery (PITR) configured. For databases that are part of business- or mission-critical applications or that need to maintain as little data loss as possible, considered enabling PITR. PITR, or Write-Ahead Logging (WAL) for MySQL, allows the restoration of data from a specific point in time, making it easier to recover from data corruption or malicious activities, such as ransomware attacks. This is because PITR provides a way to revert the database to a state before the attack occurred, minimizing the impact of the attack and reducing the amount of data that is lost. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your PostgreSQL CloudSQL instance should have PITR backups enabled refer to the Use point-in-time recovery section of the GCP PostgreSQL CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/backup-recovery/pitr",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-psql-pitr-backup-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-psql-pitr-backup-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.4] CloudSQL PostgreSQL Instances with mission-critical workloads should have point-in-time recovery (PITR) configured",
                "Description": f"CloudSQL instance {name} in {zone} has point-in-time recovery (PITR) configured.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your PostgreSQL CloudSQL instance should have PITR backups enabled refer to the Use point-in-time recovery section of the GCP PostgreSQL CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/backup-recovery/pitr",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.IP-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-4",
                        "NIST SP 800-53 Rev. 4 CP-6",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-9",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC A1.2",
                        "AICPA TSC A1.3",
                        "AICPA TSC CC3.1",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.1.3",
                        "ISO 27001:2013 A.17.2.1",
                        "ISO 27001:2013 A.18.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_private_network_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.5] CloudSQL Instances should use private networks
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # this is a PASSING check first for a change - if "privateNetwork" is not in "ipConfiguration" there isn't a VPC
        if "privateNetwork" in csql["settings"]["ipConfiguration"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-network-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-network-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.5] CloudSQL Instances should use private networks",
                "Description": f"CloudSQL instance {name} in {zone} is configured to use a private network.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should be within a private network refer to the Learn about using private IP section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/private-ip",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-network-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-network-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.5] CloudSQL Instances should use private networks",
                "Description": f"CloudSQL instance {name} in {zone} is not configured to use a private network. Configuring a Cloud SQL instance to use private IP requires private services access. Private services access lets you create private connections between your VPC network and the underlying Google service producer's VPC network. Google entities that offer services, such as Cloud SQL, are called service producers. Each Google service creates a subnet in which to provision resources. Private connections make services reachable without going through the internet or using external IP addresses. For this reason, private IP provides lower network latency than public IP and offer security benefits of limiting your attack surface. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should be within a private network refer to the Learn about using private IP section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/private-ip",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-3",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-17",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-20",
                        "NIST SP 800-53 Rev. 4 SC-15",
                        "AICPA TSC CC6.6",
                        "ISO 27001:2013 A.6.2.1",
                        "ISO 27001:2013 A.6.2.2",
                        "ISO 27001:2013 A.11.2.6",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_private_gcp_services_connection_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.6] CloudSQL Instances using private networks should enable GCP private services access
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        if "privateNetwork" in csql["settings"]["ipConfiguration"]:
            if csql["settings"]["ipConfiguration"]["enablePrivatePathForGoogleCloudServices"] == False:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-service-acess-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-service-acess-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "MEDIUM"},
                    "Confidence": 99,
                    "Title": "[GCP.CloudSQL.6] CloudSQL Instances using private networks should enable GCP private services access",
                    "Description": f"CloudSQL instance {name} in {zone} does not have GCP private services access enabled. For databases in private networks, Private services access is implemented as a VPC peering connection between your VPC network and the underlying Google Cloud VPC network where your Cloud SQL instance resides. The private connection enables VM instances in your VPC network and the services that you access to communicate exclusively by using internal IP addresses. VM instances don't need Internet access or external IP addresses to reach services that are available through private services access. Refer to the remediation instructions if this configuration is not intended.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your CloudSQL instance should have private service access enabled refer to the Configure private services access section of the GCP PostgreSQL CloudSQL guide.",
                            "Url": "https://cloud.google.com/sql/docs/mysql/configure-private-services-access",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Google CloudSQL",
                        "AssetComponent": "Database Instance"
                    },
                    "Resources": [
                        {
                            "Type": "GcpCloudSqlInstance",
                            "Id": f"{gcpProjectId}/{zone}/{name}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "GcpProjectId": gcpProjectId,
                                    "Zone": zone,
                                    "Name": name,
                                    "DatabaseVersion": databaseVersion,
                                    "MaintenanceVersion": maintenanceVersion,
                                    "CreatedAt": createTime,
                                    "State": state,
                                    "IpAddress": ipAddress
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "FAILED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.1.3",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "NEW"},
                    "RecordState": "ACTIVE"
                }
                yield finding
            else:
                finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-service-acess-check",
                    "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                    "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-private-service-acess-check",
                    "AwsAccountId": awsAccountId,
                    "Types": ["Software and Configuration Checks"],
                    "FirstObservedAt": iso8601Time,
                    "CreatedAt": iso8601Time,
                    "UpdatedAt": iso8601Time,
                    "Severity": {"Label": "INFORMATIONAL"},
                    "Confidence": 99,
                    "Title": "[GCP.CloudSQL.6] CloudSQL Instances using private networks should enable GCP private services access",
                    "Description": f"CloudSQL instance {name} in {zone} has GCP private services access enabled.",
                    "Remediation": {
                        "Recommendation": {
                            "Text": "If your CloudSQL instance should have private service access enabled refer to the Configure private services access section of the GCP PostgreSQL CloudSQL guide.",
                            "Url": "https://cloud.google.com/sql/docs/mysql/configure-private-services-access",
                        }
                    },
                    "ProductFields": {
                        "ProductName": "ElectricEye",
                        "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                        "AssetClass": "Database",
                        "AssetService": "Google CloudSQL",
                        "AssetComponent": "Database Instance"
                    },
                    "Resources": [
                        {
                            "Type": "GcpCloudSqlInstance",
                            "Id": f"{gcpProjectId}/{zone}/{name}",
                            "Partition": awsPartition,
                            "Region": awsRegion,
                            "Details": {
                                "Other": {
                                    "GcpProjectId": gcpProjectId,
                                    "Zone": zone,
                                    "Name": name,
                                    "DatabaseVersion": databaseVersion,
                                    "MaintenanceVersion": maintenanceVersion,
                                    "CreatedAt": createTime,
                                    "State": state,
                                    "IpAddress": ipAddress
                                }
                            }
                        }
                    ],
                    "Compliance": {
                        "Status": "PASSED",
                        "RelatedRequirements": [
                            "NIST CSF V1.1 PR.AC-5",
                            "NIST SP 800-53 Rev. 4 AC-4",
                            "NIST SP 800-53 Rev. 4 AC-10",
                            "NIST SP 800-53 Rev. 4 SC-7",
                            "AICPA TSC CC6.1",
                            "ISO 27001:2013 A.13.1.1",
                            "ISO 27001:2013 A.13.1.3",
                            "ISO 27001:2013 A.13.2.1",
                            "ISO 27001:2013 A.14.1.2",
                            "ISO 27001:2013 A.14.1.3"
                        ]
                    },
                    "Workflow": {"Status": "RESOLVED"},
                    "RecordState": "ARCHIVED"
                }
                yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_password_policy_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.7] CloudSQL Instances should have a password policy enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        if csql["settings"]["passwordValidationPolicy"]["enablePasswordPolicy"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.7] CloudSQL Instances should have a password policy enabled",
                "Description": f"CloudSQL instance {name} in {zone} does not have a password policy enabled. Using a comprehensive password complexity policy is important for database security to ensure strong passwords that are difficult to guess, thereby reducing the risk of unauthorized access and data theft or damage. A strong password complexity policy can prevent attackers from using automated tools to guess passwords, making it harder for them to compromise the database. Although IAM database authentication is more secure and reliable, you might prefer to use built-in authentication or a hybrid authentication model that includes both authentication types, and a strong password policy enhances the security of your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-policy-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-policy-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.7] CloudSQL Instances should have a password policy enabled",
                "Description": f"CloudSQL instance {name} in {zone} has a password policy enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_password_min_length_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.8] CloudSQL Instances should have a password minimum length requirement defined
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # Check if a "minLength" exists - who cares about length: NIST, Microsoft and CIS all say different things
        if "minLength" not in csql["settings"]["passwordValidationPolicy"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-min-length-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-min-length-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.8] CloudSQL Instances should have a password minimum length requirement defined",
                "Description": f"CloudSQL instance {name} in {zone} does not have a password minimum length requirement defined. Using a comprehensive password complexity policy is important for database security to ensure strong passwords that are difficult to guess, thereby reducing the risk of unauthorized access and data theft or damage. A strong password complexity policy can prevent attackers from using automated tools to guess passwords, making it harder for them to compromise the database. Although IAM database authentication is more secure and reliable, you might prefer to use built-in authentication or a hybrid authentication model that includes both authentication types, and a strong password policy enhances the security of your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-min-length-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-min-length-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.8] CloudSQL Instances should have a password minimum length requirement defined",
                "Description": f"CloudSQL instance {name} in {zone} has a password minimum length requirement defined.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_password_reuse_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.9] CloudSQL Instances should have a password reuse interval defined
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # Check if a "minLength" exists - who cares about length: NIST, Microsoft and CIS all say different things
        if "reuseInterval" not in csql["settings"]["passwordValidationPolicy"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.9] CloudSQL Instances should have a password reuse interval defined",
                "Description": f"CloudSQL instance {name} in {zone} does not have a password reuse interval defined. Using a comprehensive password complexity policy is important for database security to ensure strong passwords that are difficult to guess, thereby reducing the risk of unauthorized access and data theft or damage. A strong password complexity policy can prevent attackers from using automated tools to guess passwords, making it harder for them to compromise the database. Although IAM database authentication is more secure and reliable, you might prefer to use built-in authentication or a hybrid authentication model that includes both authentication types, and a strong password policy enhances the security of your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.9] CloudSQL Instances should have a password reuse interval defined",
                "Description": f"CloudSQL instance {name} in {zone} has a password reuse interval defined.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_password_username_block_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.10] CloudSQL Instances should be configured to disallow the username from being part of the password
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        if csql["settings"]["passwordValidationPolicy"]["disallowUsernameSubstring"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-username-disallowed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-username-disallowed-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.10] CloudSQL Instances should be configured to disallow the username from being part of the password",
                "Description": f"CloudSQL instance {name} in {zone} is not configured to disallow the username from being part of the password. Using a comprehensive password complexity policy is important for database security to ensure strong passwords that are difficult to guess, thereby reducing the risk of unauthorized access and data theft or damage. A strong password complexity policy can prevent attackers from using automated tools to guess passwords, making it harder for them to compromise the database. Although IAM database authentication is more secure and reliable, you might prefer to use built-in authentication or a hybrid authentication model that includes both authentication types, and a strong password policy enhances the security of your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-username-disallowed-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-username-disallowed-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.10] CloudSQL Instances should be configured to disallow the username from being part of the password",
                "Description": f"CloudSQL instance {name} in {zone} is configured to disallow the username from being part of the password.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_password_change_interval_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.11] CloudSQL Instances should have a password change interval defined
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # Check if a "minLength" exists - who cares about length: NIST, Microsoft and CIS all say different things
        if "passwordChangeInterval" not in csql["settings"]["passwordValidationPolicy"]:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-change-interval-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.11] CloudSQL Instances should have a password change interval defined",
                "Description": f"CloudSQL instance {name} in {zone} does not have a password change interval defined. Using a comprehensive password complexity policy is important for database security to ensure strong passwords that are difficult to guess, thereby reducing the risk of unauthorized access and data theft or damage. A strong password complexity policy can prevent attackers from using automated tools to guess passwords, making it harder for them to compromise the database. Although IAM database authentication is more secure and reliable, you might prefer to use built-in authentication or a hybrid authentication model that includes both authentication types, and a strong password policy enhances the security of your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-change-interval-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-instance-pw-reuse-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.11] CloudSQL Instances should have a password change interval defined",
                "Description": f"CloudSQL instance {name} in {zone} has a password change interval defined.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have have a password policy enabled or should be expanded to include more complexity refer to the Cloud SQL built-in database authentication section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/postgres/built-in-authentication#instance_password_policies",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-1",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-3",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-6",
                        "NIST SP 800-53 Rev. 4 IA-7",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 IA-9",
                        "NIST SP 800-53 Rev. 4 IA-10",
                        "NIST SP 800-53 Rev. 4 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_storage_autoresize_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.12] CloudSQL Instances should have automatic storage increase enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        if csql["settings"]["storageAutoResize"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-storage-auto-resize-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-storage-auto-resize-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.12] CloudSQL Instances should have automatic storage increase enabled",
                "Description": f"CloudSQL instance {name} in {zone} does not have automatic storage increase enabled. For important workloads that rely on the database but also continuously write to it, automatic storage increases can help avoid disruptions and loss of availability by auto-scaling provisioned disk space. If you enable this setting, Cloud SQL checks your available storage every 30 seconds. If the available storage falls below a threshold size, Cloud SQL automatically adds additional storage capacity. If the available storage repeatedly falls below the threshold size, Cloud SQL continues to add storage until it reaches the maximum of 64 TB. However, once increased the storage can not be decreased and the increases also apply to read replicas. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have automatic storage increases enabled refer to the Enable automatic storage increases section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
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
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-storage-auto-resize-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-storage-auto-resize-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.12] CloudSQL Instances should have automatic storage increase enabled",
                "Description": f"CloudSQL instance {name} in {zone} has automatic storage increase enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have automatic storage increases enabled refer to the Enable automatic storage increases section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.BE-5",
                        "NIST CSF V1.1 PR.DS-4",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC3.1",
                        "AICPA TSC A1.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.11.1.4",
                        "ISO 27001:2013 A.12.3.1",
                        "ISO 27001:2013 A.17.1.1",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding 

@registry.register_check("cloudsql")
def cloudsql_instance_deletion_protection_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.13] CloudSQL Instances should have deletion protection enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        if csql["settings"]["deletionProtectionEnabled"] == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-deletion-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.13] CloudSQL Instances should have deletion protection enabled",
                "Description": f"CloudSQL instance {name} in {zone} does not have deletion protection enabled. As part of your workload, your database can serve an important role as a data store or information repository. These databases might need to stay running indefinitely so you need a way to protect these VMs from being deleted. With Deletion Protection enabled, you have the guarantee that your database cannot be accidentally deleted. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have deletion protection enabled refer to the Instance deletion protection section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC8.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.2",
                        "ISO 27001:2013 A.14.2.2",
                        "ISO 27001:2013 A.14.2.3",
                        "ISO 27001:2013 A.14.2.4",
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
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-deletion-protection-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-deletion-protection-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.13] CloudSQL Instances should have deletion protection enabled",
                "Description": f"CloudSQL instance {name} in {zone} does not have deletion protection enabled. As part of your workload, your database can serve an important role as a data store or information repository. These databases might need to stay running indefinitely so you need a way to protect these VMs from being deleted. With Deletion Protection enabled, you have the guarantee that your database cannot be accidentally deleted. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have deletion protection enabled refer to the Instance deletion protection section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-3",
                        "NIST CSF V1.1 PR.PT-5",
                        "NIST SP 800-53 Rev. 4 AU-4",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-4",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 CP-7",
                        "NIST SP 800-53 Rev. 4 CP-8",
                        "NIST SP 800-53 Rev. 4 CP-11",
                        "NIST SP 800-53 Rev. 4 CP-13",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SA-10",
                        "NIST SP 800-53 Rev. 4 SA-14",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-6",
                        "AICPA TSC CC8.1",
                        "AICPA TSC A1.2",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.5.1",
                        "ISO 27001:2013 A.12.6.2",
                        "ISO 27001:2013 A.14.2.2",
                        "ISO 27001:2013 A.14.2.3",
                        "ISO 27001:2013 A.14.2.4",
                        "ISO 27001:2013 A.17.1.2",
                        "ISO 27001:2013 A.17.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "RESOLVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_query_insights_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.14] CloudSQL Instances should have query insights enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # "insightsConfig" can be empty or have a true / false value within
        if csql["settings"]["insightsConfig"]:
            if csql["settings"]["queryInsightsEnabled"] == True:
                insightQueryEnabled = True
            else:
                insightQueryEnabled = False
        else:
            insightQueryEnabled = False
        # failing check first...
        if insightQueryEnabled == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-query-insights-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-query-insights-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.14] CloudSQL Instances should have query insights enabled",
                "Description": f"CloudSQL instance {name} in {zone} does not have query insights enabled. Query insights helps you detect, diagnose, and prevent query performance problems for Cloud SQL databases. It supports intuitive monitoring and provides diagnostic information that helps you go beyond detection to identify the root cause of performance problems. There's no additional cost for Query insights. You can access one week of data on the Query insights dashboard. While not their intended purpose, Query insights can be used for security investigations if adversarial actions are directly taken against your database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have deletion protection enabled refer to the Instance deletion protection section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
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
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-query-insights-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-query-insights-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.14] CloudSQL Instances should have query insights enabled",
                "Description": f"CloudSQL instance {name} in {zone} has query insights enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have deletion protection enabled refer to the Instance deletion protection section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/instance-settings",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.DP-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.16.1.2",
                        "ISO 27001:2013 A.16.1.3",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cloudsql")
def cloudsql_instance_tls_enforcement_check(cache, awsAccountId, awsRegion, awsPartition, gcpProjectId):
    """
    [GCP.CloudSQL.15] CloudSQL Instances should enforce SSL/TLS connectivity
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for csql in get_cloudsql_dbs(cache, gcpProjectId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(csql,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        name = csql["name"]
        zone = csql["gceZone"]
        databaseVersion = csql["databaseVersion"]
        createTime = csql["createTime"]
        state = csql["state"]
        maintenanceVersion = csql["maintenanceVersion"]
        ipAddress = csql["ipAddresses"][0]["ipAddress"]
        # "requireSsl" is not always present if it wasn't enabled from instance creation
        if "requireSsl" in csql["settings"]["ipConfiguration"]:
            if csql["settings"]["ipConfiguration"]["requireSsl"] == False:
                tlsEnforcement = False
            else:
                tlsEnforcement = True
        else:
            tlsEnforcement = False
        # failing check first...
        if tlsEnforcement == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-tls-enforcement-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-tls-enforcement-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.15] CloudSQL Instances should enforce SSL/TLS connectivity",
                "Description": f"CloudSQL instance {name} in {zone} does not enforce SSL/TLS connectivity. Setting up your Cloud SQL instance to accept SSL/TLS connections enables SSL/TLS connections for the instance, but unencrypted and unsecure connections are still accepted. If you do not require SSL/TLS for all connections, clients without a valid certificate are allowed to connect. For this reason, if you are accessing your instance using public IP, it is strongly recommended that you enforce SSL for all connections. When the requiring SSL/TLS option is enabled, you can use either the Cloud SQL Auth proxy or SSL/TLS certificates to connect to your Cloud SQL instance. Using the Cloud SQL Auth proxy doesn't require SSL/TLS Certificates because the connection is encrypted no matter the setting. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have TLS enforcement enabled refer to the Enforce SSL/TLS encryption section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance#enforcing-ssl",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{gcpProjectId}/{zone}/{name}/cloudsql-tls-enforcement-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{gcpProjectId}/{zone}/{name}/cloudsql-tls-enforcement-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[GCP.CloudSQL.15] CloudSQL Instances should enforce SSL/TLS connectivity",
                "Description": f"CloudSQL instance {name} in {zone} does not enforce SSL/TLS connectivity. Setting up your Cloud SQL instance to accept SSL/TLS connections enables SSL/TLS connections for the instance, but unencrypted and unsecure connections are still accepted. If you do not require SSL/TLS for all connections, clients without a valid certificate are allowed to connect. For this reason, if you are accessing your instance using public IP, it is strongly recommended that you enforce SSL for all connections. When the requiring SSL/TLS option is enabled, you can use either the Cloud SQL Auth proxy or SSL/TLS certificates to connect to your Cloud SQL instance. Using the Cloud SQL Auth proxy doesn't require SSL/TLS Certificates because the connection is encrypted no matter the setting. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "If your CloudSQL instance should have TLS enforcement enabled refer to the Enforce SSL/TLS encryption section of the GCP CloudSQL guide.",
                        "Url": "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance#enforcing-ssl",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "GCP",
                    "ProviderType": "CSP",
                    "ProviderAccountId": gcpProjectId,
                    "AssetRegion": zone,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Google CloudSQL",
                    "AssetComponent": "Database Instance"
                },
                "Resources": [
                    {
                        "Type": "GcpCloudSqlInstance",
                        "Id": f"{gcpProjectId}/{zone}/{name}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "GcpProjectId": gcpProjectId,
                                "Zone": zone,
                                "Name": name,
                                "DatabaseVersion": databaseVersion,
                                "MaintenanceVersion": maintenanceVersion,
                                "CreatedAt": createTime,
                                "State": state,
                                "IpAddress": ipAddress
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.DS-2",
                        "NIST SP 800-53 Rev. 4 SC-8",
                        "NIST SP 800-53 Rev. 4 SC-11",
                        "NIST SP 800-53 Rev. 4 SC-12",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.8.2.3",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.3",
                        "ISO 27001:2013 A.14.1.2",
                        "ISO 27001:2013 A.14.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# ClientIp Query Insights Check?

# To be continued...?