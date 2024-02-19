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

from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.network import NetworkManagementClient
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_sql_servers(cache: dict, azureCredential, azSubId: str):
    """
    Returns a list of all Azure VMs in a Subscription
    """
    azSqlClient = SqlManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_sql_servers")
    if response:
        return response
    
    sqlList = [sql for sql in azSqlClient.servers.list()]
    if not sqlList or sqlList is None:
        sqlList = []

    cache["get_all_sql_servers"] = sqlList
    return cache["get_all_sql_servers"]

@registry.register_check("azure.sql_server")
def azure_sql_server_server_level_auditing_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.SQLServer.1] Azure SQL Server should have Auditing enabled at the server level
    """
    azSqlClient = SqlManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sqlserv in get_all_sql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sqlserv,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        sqlservName = sqlserv.name
        sqlservId = str(sqlserv.id)
        azRegion = sqlserv.location
        rgName = sqlservId.split("/")[4]
        serverAuditingSettings = azSqlClient.server_blob_auditing_policies.get(rgName,sqlservName)
        serverAuditEnabled = False
        if serverAuditingSettings.state == "Enabled":
            if serverAuditingSettings.is_azure_monitor_target_enabled is not None or serverAuditingSettings.storage_account_subscription_id is not None or serverAuditingSettings.storage_account_subscription_id != "00000000-0000-0000-0000-000000000000":
                serverAuditEnabled = True

        # this is a failing check
        if serverAuditEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-auditing-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-auditing-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.1] Azure SQL Server should have Auditing enabled at the server level",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} does not have auditing enabled. The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted. Auditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server auditing, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.1",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-auditing-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-auditing-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.1] Azure SQL Server should have Auditing enabled at the server level",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} has auditing enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server auditing, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 ID.AM-3",
                        "NIST CSF V1.1 DE.AE-1",
                        "NIST CSF V1.1 DE.AE-3",
                        "NIST CSF V1.1 DE.CM-1",
                        "NIST CSF V1.1 DE.CM-7",
                        "NIST CSF V1.1 PR.PT-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 AU-12",
                        "NIST SP 800-53 Rev. 4 CA-3",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-9",
                        "NIST SP 800-53 Rev. 4 CM-2",
                        "NIST SP 800-53 Rev. 4 CM-3",
                        "NIST SP 800-53 Rev. 4 CM-8",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PE-3",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 PE-20",
                        "NIST SP 800-53 Rev. 4 PL-8",
                        "NIST SP 800-53 Rev. 4 SC-5",
                        "NIST SP 800-53 Rev. 4 SC-7",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.1.1",
                        "ISO 27001:2013 A.12.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.2",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.12.4.4",
                        "ISO 27001:2013 A.12.7.1",
                        "ISO 27001:2013 A.13.1.1",
                        "ISO 27001:2013 A.13.2.1",
                        "ISO 27001:2013 A.13.2.2",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1",
                        "ISO 27001:2013 A.16.1.7",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.1",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_sql_server_no_ingress_from_internet_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.SQLServer.2] Azure SQL Server should not allow ingress from the internet (0.0.0.0/0) to the server
    """
    azSqlClient = SqlManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sqlserv in get_all_sql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sqlserv,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        sqlservName = sqlserv.name
        sqlservId = str(sqlserv.id)
        azRegion = sqlserv.location
        rgName = sqlservId.split("/")[4]
        serverFirewallRules = azSqlClient.firewall_rules.list_by_server(rgName,sqlservName)
        allowInternetIngress = False
        for rule in serverFirewallRules:
            if rule.start_ip_address == "0.0.0.0":
                allowInternetIngress = True
                break

        # this is a failing check
        if allowInternetIngress is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-no-internet-ingress-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-no-internet-ingress-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.2] Azure SQL Server should not allow ingress from the internet (0.0.0.0/0) to the server",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} allows ingress from the internet. Azure SQL Database and Azure SQL Managed Instance support the ability to create firewall rules to allow specific IP addresses to access your servers. It is recommended to restrict access to your Azure SQL Server to only the IP addresses that require access. By default, the Azure SQL Server firewall is configured to allow all Azure services to access your server. This configuration is not recommended for production environments. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server firewall rules, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
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
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.2",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-no-internet-ingress-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-no-internet-ingress-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.2] Azure SQL Server should not allow ingress from the internet (0.0.0.0/0) to the server",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} does not allow ingress from the internet.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server firewall rules, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
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
                        "ISO 27001:2013 A.13.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.2",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_sql_server_tde_with_cmk_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.SQLServer.3] Azure SQL Servers should use Transparent Data Encryption (TDE) with Customer Managed Keys (CMK)
    """
    azSqlClient = SqlManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sqlserv in get_all_sql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sqlserv,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        sqlservName = sqlserv.name
        sqlservId = str(sqlserv.id)
        azRegion = sqlserv.location
        rgName = sqlservId.split("/")[4]
        tdeProtector = azSqlClient.encryption_protectors.get(rgName,sqlservName,"current")
        tdeWithCmk = False
        if tdeProtector.server_key_type != "ServiceManaged":
            tdeWithCmk = True

        # this is a failing check
        if tdeWithCmk is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-tde-with-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-tde-with-cmk-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.3] Azure SQL Servers should use Transparent Data Encryption (TDE) with Customer Managed Keys (CMK)",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} does not use Transparent Data Encryption (TDE) with Customer Managed Keys (CMK). Transparent Data Encryption (TDE) helps protect Azure SQL Database and Azure SQL Managed Instance against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application. TDE with Customer Managed Keys (CMK) allows you to bring your own key to encrypt the database. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server Transparent Data Encryption, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-tde-with-cmk-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-tde-with-cmk-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.3] Azure SQL Servers should use Transparent Data Encryption (TDE) with Customer Managed Keys (CMK)",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} uses Transparent Data Encryption (TDE) with Customer Managed Keys (CMK).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server Transparent Data Encryption, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_sql_server_entra_id_admin_authentication_configured_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.SQLServer.4] Azure SQL Server should have Microsoft Entra ID authentication configured for server admin
    """
    azSqlClient = SqlManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for sqlserv in get_all_sql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(sqlserv,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        sqlservName = sqlserv.name
        sqlservId = str(sqlserv.id)
        azRegion = sqlserv.location
        rgName = sqlservId.split("/")[4]
        serverAdmin = azSqlClient.server_azure_ad_administrators.list_by_server(rgName,sqlservName)
        aadAdminConfigured = False
        for admin in serverAdmin:
            if admin.administrator_type == "ActiveDirectory":
                aadAdminConfigured = True
                break

        # this is a failing check
        if aadAdminConfigured is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-entra-id-admin-authentication-configured-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-entra-id-admin-authentication-configured-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.4] Azure SQL Server should have Microsoft Entra ID authentication configured for server admin",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} does not have Microsoft Entra ID authentication configured for the server admin. Azure SQL Database and Azure SQL Managed Instance support the ability to use Azure Active Directory (AAD) to authenticate the server admin. This provides a more secure and manageable way to authenticate to your SQL Server. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server Azure Active Directory authentication, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.4",
                        "MITRE ATT&CK T1078.004"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-entra-id-admin-authentication-configured-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{sqlservId}/azure-sqlserver-entra-id-admin-authentication-configured-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.SQLServer.4] Azure SQL Server should have Microsoft Entra ID authentication configured for server admin",
                "Description": f"Azure SQL Server {sqlservName} in Subscription {azSubId} in {azRegion} has Microsoft Entra ID authentication configured for the server admin.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Azure SQL Server Azure Active Directory authentication, refer to the Azure documentation",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Database",   
                    "AssetService": "Azure SQL Server",
                    "AssetComponent": "Server",
                },
                "Resources": [
                    {
                        "Type": "AzureSqlServer",
                        "Id": sqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": sqlservName,
                                "Id": sqlservId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.AC-6",
                        "NIST SP 800-53 Rev. 4 AC-1",
                        "NIST SP 800-53 Rev. 4 AC-2",
                        "NIST SP 800-53 Rev. 4 AC-3",
                        "NIST SP 800-53 Rev. 4 AC-16",
                        "NIST SP 800-53 Rev. 4 AC-19",
                        "NIST SP 800-53 Rev. 4 AC-24",
                        "NIST SP 800-53 Rev. 4 IA-1",
                        "NIST SP 800-53 Rev. 4 IA-2",
                        "NIST SP 800-53 Rev. 4 IA-4",
                        "NIST SP 800-53 Rev. 4 IA-5",
                        "NIST SP 800-53 Rev. 4 IA-8",
                        "NIST SP 800-53 Rev. 4 PE-2",
                        "NIST SP 800-53 Rev. 4 PS-3",
                        "AICPA TSC CC6.1",
                        "ISO 27001:2013 A.7.1.1",
                        "ISO 27001:2013 A.9.2.1",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.1.4",
                        "MITRE ATT&CK T1078.004"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??