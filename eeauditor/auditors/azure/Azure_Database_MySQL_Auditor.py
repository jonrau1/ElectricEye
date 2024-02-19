from azure.mgmt.rdbms import mysql_flexibleservers
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_mysql_servers(cache: dict, azureCredential, azSubId: str):
    """
    Returns a list of all Azure Database for MySQL Servers in a Subscription
    """
    azMysqlClient = mysql_flexibleservers.MySQLManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_mysql_servers")
    if response:
        return response

    sqlList = [serv for serv in azMysqlClient.servers.list()]
    if not sqlList or sqlList is None:
        sqlList = []

    cache["get_all_mysql_servers"] = sqlList
    return cache["get_all_mysql_servers"]

@registry.register_check("azure.sql_server")
def azure_db_for_mysql_flexible_server_enforce_ssl_connection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.MySQLDatabase.1] Azure Database for MySQL flexible servers should enforce SSL connections
    """
    azMysqlClient = mysql_flexibleservers.MySQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_mysql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        mysqlservName = serv.name
        mysqlservId = str(serv.id)
        azRegion = serv.location
        rgName = mysqlservId.split("/")[4]
        enforceTls = False
        enforceTlsParameter = [
            param.as_dict() for param in azMysqlClient.configurations.list_by_server(rgName, mysqlservName) if str(param.name) == "require_secure_transport"
        ][0]
        if enforceTlsParameter["value"] == "ON":
            enforceTls = True

        # this is a failing check
        if enforceTls is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-ssl-connectivity-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-ssl-connectivity-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.1] Azure Database for MySQL flexible servers should enforce SSL connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} does not enforce secure transport (SSL connections). Azure Database for MySQL flexible server supports connecting your client applications to the Azure Database for MySQL flexible server instance using Secure Sockets Layer (SSL) with Transport layer security(TLS) encryption. TLS is an industry standard protocol that ensures encrypted network connections between your database server and client applications, allowing you to adhere to compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing SSL connections for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.1",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-ssl-connectivity-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-ssl-connectivity-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.1] Azure Database for MySQL flexible servers should enforce SSL connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} enforces secure transport (SSL connections).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing SSL connections for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.1",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_db_for_mysql_flexible_server_tls12_minimum_version_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.MySQLDatabase.2] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections
    """
    azMysqlClient = mysql_flexibleservers.MySQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_mysql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        mysqlservName = serv.name
        mysqlservId = str(serv.id)
        azRegion = serv.location
        rgName = mysqlservId.split("/")[4]
        tls12Enforcement = False
        enforceTlsParameter = [
            param.as_dict() for param in azMysqlClient.configurations.list_by_server(rgName, mysqlservName) if str(param.name) == "tls_version"
        ][0]
        if enforceTlsParameter["value"] == "TLSv1.2" or enforceTlsParameter["value"] == "TLSv1.3":
            tls12Enforcement = True

        # this is a failing check
        if tls12Enforcement is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.2] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} does not enforce TLS 1.2 as the minimum TLS version for secure connections. Azure Database for MySQL flexible server supports connecting your client applications to the Azure Database for MySQL flexible server instance using Secure Sockets Layer (SSL) with Transport layer security(TLS) encryption. TLS is an industry standard protocol that ensures encrypted network connections between your database server and client applications, allowing you to adhere to compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.2",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.2] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} enforces TLS 1.2 as the minimum TLS version for secure connections.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.2",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_db_for_mysql_flexible_server_tls12_minimum_version_for_admin_connections_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.MySQLDatabase.3] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure administrator connections
    """
    azMysqlClient = mysql_flexibleservers.MySQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_mysql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        mysqlservName = serv.name
        mysqlservId = str(serv.id)
        azRegion = serv.location
        rgName = mysqlservId.split("/")[4]
        adminTls12Enforcement = False
        enforceTlsParameter = [
            param.as_dict() for param in azMysqlClient.configurations.list_by_server(rgName, mysqlservName) if str(param.name) == "admin_tls_version"
        ][0]
        if enforceTlsParameter["value"] == "TLSv1.2" or enforceTlsParameter["value"] == "TLSv1.3":
            adminTls12Enforcement = True
        
        # this is a failing check
        if adminTls12Enforcement is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-for-admin-connections-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-for-admin-connections-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.3] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure administrator connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} does not enforce TLS 1.2 as the minimum TLS version for secure administrator connections. Azure Database for MySQL flexible server supports connecting your client applications to the Azure Database for MySQL flexible server instance using Secure Sockets Layer (SSL) with Transport layer security(TLS) encryption. TLS is an industry standard protocol that ensures encrypted network connections between your database server and client applications, allowing you to adhere to compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.2",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-for-admin-connections-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-tls12-minimum-version-for-admin-connections-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.3] Azure Database for MySQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure administrator connections",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} enforces TLS 1.2 as the minimum TLS version for secure administrator connections.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for Azure Database for MySQL flexible servers, refer to the Connect to Azure Database for MySQL - Flexible Server with encrypted connections section of the Azure MySQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.2",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.sql_server")
def azure_db_for_mysql_flexible_server_audit_logging_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.MySQLDatabase.4] Azure Database for MySQL flexible servers should have audit logging enabled
    """
    azMysqlClient = mysql_flexibleservers.MySQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_mysql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        mysqlservName = serv.name
        mysqlservId = str(serv.id)
        azRegion = serv.location
        rgName = mysqlservId.split("/")[4]
        auditLogEnabled = False
        enforceTlsParameter = [
            param.as_dict() for param in azMysqlClient.configurations.list_by_server(rgName, mysqlservName) if str(param.name) == "audit_log_enabled"
        ][0]
        if enforceTlsParameter["value"] == "ON":
            auditLogEnabled = True

        # this is a failing check
        if auditLogEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-audit-logging-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-audit-logging-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.4] Azure Database for MySQL flexible servers should have audit logging enabled",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} does not have audit logging enabled. Azure Database for MySQL flexible server supports audit logging to track database events. Audit logs provide a way to monitor and record database activities and can be used to help meet compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling audit logging for Azure Database for MySQL flexible servers, refer to the Configure and access audit logs for Azure Database for MySQL in the Azure portal section of the Azure MySQL documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-audit-logs-portal"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-audit-logging-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azSubId}/{azRegion}/{mysqlservId}/azure-database-for-mysql-server-audit-logging-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.MySQLDatabase.4] Azure Database for MySQL flexible servers should have audit logging enabled",
                "Description": f"Azure Database for MySQL Server {mysqlservName} in Subscription {azSubId} in {azRegion} has audit logging enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling audit logging for Azure Database for MySQL flexible servers, refer to the Configure and access audit logs for Azure Database for MySQL in the Azure portal section of the Azure MySQL documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-audit-logs-portal"
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
                    "AssetService": "Azure Database for MySQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": mysqlservId,
                        "Partition": awsPartition,
                        "Region": azRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": mysqlservName,
                                "Id": mysqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# END ??