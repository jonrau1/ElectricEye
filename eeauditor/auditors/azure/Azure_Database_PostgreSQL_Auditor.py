from azure.mgmt.rdbms import postgresql_flexibleservers
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_postgresql_servers(cache: dict, azureCredential, azSubId: str):
    """
    Returns a list of all Azure Database for PostgreSQL Servers in a Subscription
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_postgresql_servers")
    if response:
        return response

    sqlList = [serv for serv in azPostgresqlClient.servers.list()]
    if not sqlList or sqlList is None:
        sqlList = []

    cache["get_all_postgresql_servers"] = sqlList
    return cache["get_all_postgresql_servers"]

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_flexible_server_enforce_ssl_connection_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.1] Azure Database for PostgreSQL flexible servers should enforce SSL connections
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        enforceTls = False
        enforceTlsParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "require_secure_transport"
        ][0]
        if enforceTlsParameter["value"] == "on":
            enforceTls = True

        # this is a failing check
        if enforceTls is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-ssl-connectivity-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-ssl-connectivity-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.1] Azure Database for PostgreSQL flexible servers should enforce SSL connections",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not enforce secure transport (SSL connections). Azure Database for PostgreSQL flexible server supports connecting your client applications to the Azure Database for PostgreSQL flexible server instance using Secure Sockets Layer (SSL) with Transport layer security(TLS) encryption. TLS is an industry standard protocol that ensures encrypted network connections between your database server and client applications, allowing you to adhere to compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing SSL connections for Azure Database for PostgreSQL flexible servers refer to the Secure connectivity with TLS and SSL in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-ssl-tls"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.1",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-ssl-connectivity-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-ssl-connectivity-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.1] Azure Database for PostgreSQL flexible servers should enforce SSL connections",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does enforce secure transport (SSL connections).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing SSL connections for Azure Database for PostgreSQL flexible servers refer to the Secure connectivity with TLS and SSL in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-ssl-tls"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.1",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_tls_12_minimum_version_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.2] Azure Database for PostgreSQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        enforceTls12 = False
        enforceTls12Parameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "ssl_min_protocol_version"
        ][0]
        if enforceTls12Parameter["value"] == "TLSv1.2" or enforceTls12Parameter["value"] == "TLSv1.3":
            enforceTls12 = True

        # this is a failing check
        if enforceTls12 is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-tls-12-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-tls-12-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.2] Azure Database for PostgreSQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not enforce TLS 1.2 as the minimum TLS version for secure connections. Azure Database for PostgreSQL flexible server supports connecting your client applications to the Azure Database for PostgreSQL flexible server instance using Secure Sockets Layer (SSL) with Transport layer security(TLS) encryption. TLS is an industry standard protocol that ensures encrypted network connections between your database server and client applications, allowing you to adhere to compliance requirements. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for secure connections for Azure Database for PostgreSQL flexible servers refer to the Secure connectivity with TLS and SSL in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-ssl-tls"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.1",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-tls-12-minimum-version-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-tls-12-minimum-version-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.2] Azure Database for PostgreSQL flexible servers should enforce TLS 1.2 as the minimum TLS version for secure connections",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does enforce TLS 1.2 as the minimum TLS version for secure connections.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enforcing TLS 1.2 as the minimum TLS version for secure connections for Azure Database for PostgreSQL flexible servers refer to the Secure connectivity with TLS and SSL in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-ssl-tls"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.1",
                        "MITRE ATT&CK T1040"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_log_checkpoints_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.3] Azure Database for PostgreSQL flexible servers should ensure that the 'log_checkpoints' parameter is enabled
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        logCheckpointEnabled = False
        logCheckpointsParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "log_checkpoints"
        ][0]
        if str(logCheckpointsParameter["value"]).lower() == "on":
            logCheckpointEnabled = True

        # this is a failing check
        if logCheckpointEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-checkpoints-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-checkpoints-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.3] Azure Database for PostgreSQL flexible servers should ensure that the 'log_checkpoints' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'log_checkpoints' parameter enabled. The 'log_checkpoints' parameter causes checkpoints and restartpoints to be logged in the server log. Some statistics are included in the log messages, including the number of buffers written and the time spent writing them. Enabling this parameter is important for monitoring and troubleshooting purposes. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_checkpoints' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.2",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-checkpoints-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-checkpoints-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.3] Azure Database for PostgreSQL flexible servers should ensure that the 'log_checkpoints' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does have the 'log_checkpoints' parameter enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_checkpoints' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.2",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_log_connections_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_connections' parameter is enabled
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        logConnectionsEnabled = False
        logConnectionsParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "log_connections"
        ][0]
        if str(logConnectionsParameter["value"]).lower() == "on":
            logConnectionsEnabled = True

        # this is a failing check
        if logConnectionsEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-connections-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-connections-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_connections' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'log_connections' parameter enabled. The 'log_connections' parameter causes each successful connection to the server to be logged. This is useful for tracking when clients are connecting to the server. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_connections' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.3",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-connections-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-connections-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_connections' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does have the 'log_connections' parameter enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_connections' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.3",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_log_disconnections_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_disconnections' parameter is enabled
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        logDisconnectionsEnabled = False
        logDisconnectionsParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "log_disconnections"
        ][0]
        if str(logDisconnectionsParameter["value"]).lower() == "on":
            logDisconnectionsEnabled = True

        # this is a failing check
        if logDisconnectionsEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-disconnections-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-disconnections-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_disconnections' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'log_disconnections' parameter enabled. The 'log_disconnections' parameter causes each unsuccessful connection attempt to be logged. This is useful for tracking when clients are failing to connect to the server. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_disconnections' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.4",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-disconnections-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-log-disconnections-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.4] Azure Database for PostgreSQL flexible servers should ensure that the 'log_disconnections' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does have the 'log_disconnections' parameter enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'log_disconnections' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.4",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_connection_throttling_enabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.6] Azure Database for PostgreSQL flexible servers should ensure that the 'connection_throttling' parameter is enabled
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        connectionThrottlingEnabled = False
        connectionthrottlingParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "connection_throttle.enable"
        ][0]
        if str(connectionthrottlingParameter["value"]).lower() == "on":
            connectionThrottlingEnabled = True

        # this is a failing check
        if connectionThrottlingEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-connection-throttling-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-connection-throttling-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.6] Azure Database for PostgreSQL flexible servers should ensure that the 'connection_throttling' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'connection_throttling' parameter enabled. The 'connection_throttling' parameter chelps the PostgreSQL Database to Set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'connection_throttling' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.5",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-connection-throttling-enabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-connection-throttling-enabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.6] Azure Database for PostgreSQL flexible servers should ensure that the 'connection_throttling' parameter is enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does have the 'connection_throttling' parameter enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling the 'connection_throttling' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.5",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_retain_logs_for_at_least_3_days_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.7] Azure Database for PostgreSQL flexible servers should ensure that the 'log_retention_days' parameter is enabled and configure for greater than 3 days
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        logRetentionDaysGreaterThanThree = False
        logRetentionDaysGreaterThanThreeParameter = [
            param.as_dict() for param in azPostgresqlClient.configurations.list_by_server(rgName, postgresqlservName) if str(param.name) == "log_retention_days"
        ]
        if logRetentionDaysGreaterThanThreeParameter:
            if str(logRetentionDaysGreaterThanThreeParameter[0]["value"]).lower() == "on":
                logRetentionDaysGreaterThanThree = True

        # this is a failing check
        if logRetentionDaysGreaterThanThree is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-retain-logs-for-at-least-3-days-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-retain-logs-for-at-least-3-days-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.7] Azure Database for PostgreSQL flexible servers should ensure that the 'log_retention_days' parameter is enabled and configure for greater than 3 days",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'log_retention_days' parameter enabled or configured for greater than 3 days. Configuring 'log_retention_days' determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance. Configuring this setting will result in logs being retained for the specified number of days. If this is configured on a high traffic server, the log may grow quickly to occupy a large amount of disk space. In this case you may want to set this to a lower number. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling and configuring the 'log_retention_days' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.6",
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-retain-logs-for-at-least-3-days-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-retain-logs-for-at-least-3-days-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFOMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.7] Azure Database for PostgreSQL flexible servers should ensure that the 'log_retention_days' parameter is enabled and configure for greater than 3 days",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have the 'log_retention_days' parameter enabled or configured for greater than 3 days.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling and configuring the 'log_retention_days' parameter for Azure Database for PostgreSQL flexible servers refer to the Server parameters in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-server-parameters"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.6",
                        "MITRE ATT&CK T1485"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_access_to_azure_services_disabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.8] Azure Database for PostgreSQL flexible servers should disable unfettered access to Azure services
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        azureServicesAccessEnabled = False
        fwRules = azPostgresqlClient.firewall_rules.list_by_server(rgName, postgresqlservName)
        for fwRule in fwRules:
            if "azureservices" in str(fwRule.name).lower() and str(fwRule.start_ip_address) == "0.0.0.0":
                azureServicesAccessEnabled = True
                break

        # this is a failing check
        if azureServicesAccessEnabled is True:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-access-to-azure-services-disabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-access-to-azure-services-disabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.8] Azure Database for PostgreSQL flexible servers should disable unfettered access to Azure services",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} has a firewall rule enabled that allows all Azure services to access the database. If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on providing access to Azure services to your Azure Database for PostgreSQL flexible servers refer to the Firewall rules in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "Microsoft Azure Foundations Benchmark V2.0.0 4.3.7",
                        "MITRE ATT&CK T1613"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-access-to-azure-services-disabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-access-to-azure-services-disabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFOMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.8] Azure Database for PostgreSQL flexible servers should disable unfettered access to Azure services",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have a firewall rule enabled that allows all Azure services to access the database.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on providing access to Azure services to your Azure Database for PostgreSQL flexible servers refer to the Firewall rules in Azure Database for PostgreSQL - Flexible Server section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "ISO 27001:2013 A.14.1.3",
                        "Microsoft Azure Foundations Benchmark V2.0.0 4.3.7",
                        "MITRE ATT&CK T1613"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_public_network_access_disabled_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.9] Azure Database for PostgreSQL flexible servers should have public network access disabled
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        # this is a failing check
        if serv.network.public_network_access == "Enabled":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-public-network-access-disabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-public-network-access-disabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDUIM"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.9] Azure Database for PostgreSQL flexible servers should have public network access disabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} has public network access enabled. When you choose the Public Access method, your Azure Database for PostgreSQL flexible server instance is accessed through a public endpoint over the internet. The public endpoint is a publicly resolvable DNS address. The phrase allowed IP addresses refers to a range of IP addresses that you choose to give permission to access your server. These permissions are called firewall rules. Characteristics of the public access method include: your Azure Database for PostgreSQL flexible server instance has a publicly resolvable DNS name, however, only the IP addresses that you allow have permission to access your Azure Database for PostgreSQL flexible server instance. By default, no IP addresses are allowed. You can add IP addresses during server creation or afterward. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on providing network access to your Azure Database for PostgreSQL flexible servers refer to the Networking overview for Azure Database for PostgreSQL - Flexible Server with public access (allowed IP addresses) section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-public"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-public-network-access-disabled-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-public-network-access-disabled-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFOMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.9] Azure Database for PostgreSQL flexible servers should have public network access disabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} has public network access disabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on providing network access to your Azure Database for PostgreSQL flexible servers refer to the Networking overview for Azure Database for PostgreSQL - Flexible Server with public access (allowed IP addresses) section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-public"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSSED",
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

@registry.register_check("azure.azure_db_for_postgresql_server")
def azure_db_for_postgresql_double_encryption_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.PostgreSQLDatabase.10] Azure Database for PostgreSQL flexible servers running regulated workloads should have double encryption enabled
    """
    azPostgresqlClient = postgresql_flexibleservers.PostgreSQLManagementClient(azureCredential, azSubId)
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for serv in get_all_postgresql_servers(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(serv.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        postgresqlservName = serv.name
        postgresqlservId = str(serv.id)
        azRegion = serv.location
        rgName = postgresqlservId.split("/")[4]
        doubleEncryptionEnabled = False
        try:
            config = azPostgresqlClient.configurations.get(rgName,postgresqlservName,"azure.infrastructure_encryption")
            if config.value == "Enabled":
                doubleEncryptionEnabled = True
        except Exception as e:
            if "ConfigurationNotExists" in str(e):
                config = None
        
        # this is a failing check
        if doubleEncryptionEnabled is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-double-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-double-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.10] Azure Database for PostgreSQL flexible servers running regulated workloads should have double encryption enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does not have double encryption enabled. Azure Database for PostgreSQL flexible servers should have double encryption enabled to ensure that data at rest is encrypted with a key that is protected by a customer-managed key. This is especially important for regulated workloads that require double encryption. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling double encryption for your Azure Database for PostgreSQL flexible servers refer to the Azure Database for PostgreSQL Infrastructure double encryption section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-infrastructure-double-encryption"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.8"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-double-encryption-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{postgresqlservId}/azure-database-for-postgresql-server-double-encryption-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFOMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.PostgreSQLDatabase.10] Azure Database for PostgreSQL flexible servers running regulated workloads should have double encryption enabled",
                "Description": f"Azure Database for PostgreSQL Server {postgresqlservName} in Subscription {azSubId} in {azRegion} does have double encryption enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on enabling double encryption for your Azure Database for PostgreSQL flexible servers refer to the Azure Database for PostgreSQL Infrastructure double encryption section of the Azure PostgreSQL documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-infrastructure-double-encryption"
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
                    "AssetService": "Azure Database for PostgreSQL Server",
                    "AssetComponent": "Server"
                },
                "Resources": [
                    {
                        "Type": "AzureDatabaseForMySqlServer",
                        "Id": postgresqlservId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": postgresqlservName,
                                "Id": postgresqlservId
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
                        "CIS Microsoft Azure Foundations Benchmark V2.0.0 4.3.8"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        
## END ??