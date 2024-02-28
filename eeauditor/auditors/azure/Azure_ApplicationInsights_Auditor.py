from azure.mgmt.applicationinsights import ApplicationInsightsManagementClient, models
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

def get_all_app_insights_components(cache: dict, azureCredential, azSubId: str) -> list[models.ApplicationInsightsComponent]:
    """
    Returns a list of all Azure Database for MySQL Servers in a Subscription
    """
    azAppInsightsClient = ApplicationInsightsManagementClient(azureCredential, azSubId)

    response = cache.get("get_all_app_insights_components")
    if response:
        return response

    appInsightsList = [serv for serv in azAppInsightsClient.components.list()]
    if not appInsightsList or appInsightsList is None:
        appInsightsList = []

    cache["get_all_app_insights_components"] = appInsightsList
    return cache["get_all_app_insights_components"]

@registry.register_check("azure.application_insights")
def azure_app_insights_enabled_for_subscription_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.ApplicationInsights.1] Azure Application Insights should be configured in at least one region within a Subscription to provide Application Performance Monitoring (APM) capabilities
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    appInsightsComponents = get_all_app_insights_components(cache, azureCredential, azSubId)
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(appInsightsComponents,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    if not appInsightsComponents:
        # this is a failing check
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{azSubId}/azure-application-insights-enabled-for-subscription-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{azSubId}/azure-application-insights-enabled-for-subscription-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "LOW"},
            "Confidence": 99,
            "Title": "[Azure.ApplicationInsights.1] Azure Application Insights should be configured in at least one region within a Subscription to provide Application Performance Monitoring (APM) capabilities",
            "Description": f"An Azure Applicaiton Insights component is not configured in Subscription {azSubId}. Application Insights within Azure act as an Application Performance Monitoring solution providing valuable data into how well an application performs and additional information when performing incident response. The types of log data collected include application metrics, telemetry data, and application trace logging data providing organizations with detailed information about application activity and application transactions. Both data sets help organizations adopt a proactive and retroactive means to handle security and performance related metrics within their modern applications. Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Application Insights and how to deploy it refer to the Application Insights overview section of the Azure Monitor documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Azure Application Insights",
                "AssetComponent": "Component"
            },
            "Resources": [
                {
                    "Type": "AzureApplicationInsightsComponent",
                    "Id": azSubId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 5.3.1",
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
            "Id": f"{azSubId}/azure-application-insights-enabled-for-subscription-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"{azSubId}/azure-application-insights-enabled-for-subscription-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Azure.ApplicationInsights.1] Azure Application Insights should be configured in at least one region within a Subscription to provide Application Performance Monitoring (APM) capabilities",
            "Description": f"An Azure Applicaiton Insights component is configured in Subscription {azSubId}.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on Application Insights and how to deploy it refer to the Application Insights overview section of the Azure Monitor documentation.",
                    "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Azure",
                "ProviderType": "CSP",
                "ProviderAccountId": azSubId,
                "AssetRegion": "azure-global",
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Azure Application Insights",
                "AssetComponent": "Component"
            },
            "Resources": [
                {
                    "Type": "AzureApplicationInsightsComponent",
                    "Id": azSubId,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SubscriptionId": azSubId
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
                    "CIS Microsoft Azure Foundations Benchmark V2.0.0 5.3.1",
                    "MITRE ATT&CK T1190"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding

@registry.register_check("azure.application_insights")
def azure_app_insights_log_analytics_ingestion_mode_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.ApplicationInsights.2] Azure Application Insights should be configured to send telemetry data to an Azure Log Analytics Workspace
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for component in get_all_app_insights_components(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(component.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appInsightCompName = component.name
        appInsightCompId = str(component.id)
        azRegion = component.location
        rgName = appInsightCompId.split("/")[4]
        # this is a failing check
        if component.ingestion_mode != "LogAnalytics":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-log-analytics-ingestion-mode-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-log-analytics-ingestion-mode-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.2] Azure Application Insights should be configured to send telemetry data to an Azure Log Analytics Workspace",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is not configured to send telemetry data to an Azure Log Analytics Workspace. Application Insights within Azure act as an Application Performance Monitoring solution providing valuable data into how well an application performs and additional information when performing incident response. The types of log data collected include application metrics, telemetry data, and application trace logging data providing organizations with detailed information about application activity and application transactions. Both data sets help organizations adopt a proactive and retroactive means to handle security and performance related metrics within their modern applications. Configuring Application Insights to send telemetry data to an Azure Log Analytics Workspace provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Follow the instructions to configure Application Insights to send telemetry data to an Azure Log Analytics Workspace in the Azure Monitor documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-monitor/app/azure-log-analytics"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-log-analytics-ingestion-mode-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-log-analytics-ingestion-mode-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.2] Azure Application Insights should be configured to send telemetry data to an Azure Log Analytics Workspace",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is configured to send telemetry data to an Azure Log Analytics Workspace.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "Follow the instructions to configure Application Insights to send telemetry data to an Azure Log Analytics Workspace in the Azure Monitor documentation.",
                        "Url": "https://docs.microsoft.com/en-us/azure/azure-monitor/app/azure-log-analytics"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.application_insights")
def azure_app_insights_disable_local_auth_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.ApplicationInsights.3] Azure Application Insights should be configured to disable local authentication
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for component in get_all_app_insights_components(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(component.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appInsightCompName = component.name
        appInsightCompId = str(component.id)
        azRegion = component.location
        rgName = appInsightCompId.split("/")[4]
        # this is a failing check
        if component.disable_local_auth is False or component.disable_local_auth is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-local-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-local-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.3] Azure Application Insights should be configured to disable local authentication",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is not configured to disable local authentication. Application Insights now supports Microsoft Entra authentication. By using Microsoft Entra ID, you can ensure that only authenticated telemetry is ingested in your Application Insights resources. Using various authentication systems can be cumbersome and risky because it's difficult to manage credentials at scale. You can now choose to opt out of local authentication to ensure only telemetry exclusively authenticated by using managed identities and Microsoft Entra ID is ingested in your resource. This feature is a step to enhance the security and reliability of the telemetry used to make critical operational (alerting and autoscaling) and business decisions. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Microsoft Entra ID authentication for Application Insights and for instructions to disable local authentication refer to the Microsoft Entra authentication for Application Insights section in the Azure Monitor documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/azure-ad-authentication?tabs=net#disable-local-authentication"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-local-auth-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-local-auth-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.3] Azure Application Insights should be configured to disable local authentication",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is configured to disable local authentication.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on Microsoft Entra ID authentication for Application Insights and for instructions to disable local authentication refer to the Microsoft Entra authentication for Application Insights section in the Azure Monitor documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/azure-ad-authentication?tabs=net#disable-local-authentication"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                        "ISO 27001:2013 A.9.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("azure.application_insights")
def azure_app_insights_disable_ip_masking_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, azureCredential, azSubId: str) -> dict:
    """
    [Azure.ApplicationInsights.4] Azure Application Insights should be configured to disable IP masking
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for component in get_all_app_insights_components(cache, azureCredential, azSubId):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(component.as_dict(),default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        appInsightCompName = component.name
        appInsightCompId = str(component.id)
        azRegion = component.location
        rgName = appInsightCompId.split("/")[4]
        # this is a failing check
        if component.disable_ip_masking is False or component.disable_ip_masking is None:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-ip-masking-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-ip-masking-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.4] Azure Application Insights should be configured to disable IP masking",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is not configured to disable IP masking. By default, IP addresses are temporarily collected but not stored in Application Insights. This process follows some basic steps. When telemetry is sent to Azure, Application Insights uses the IP address to do a geolocation lookup. Application Insights uses the results of this lookup to populate the fields client_City, client_StateOrProvince, and client_CountryOrRegion. The address is then discarded, and 0.0.0.0 is written to the client_IP field. Although the default is to not collect IP addresses, you can override this behavior. Azure recommends verifying that the collection doesn't break any compliance requirements or local regulations. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on IP masking refer to the Geolocation and IP address handling section in the Azure Monitor documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/ip-collection?tabs=framework%2Cnodejs#storage-of-ip-address-data"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                "Id": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-ip-masking-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{azRegion}/{appInsightCompId}/azure-application-insights-disable-ip-masking-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Azure.ApplicationInsights.4] Azure Application Insights should be configured to disable IP masking",
                "Description": f"Azure Application Insights component {appInsightCompName} in Subscription {azSubId} in {azRegion} is configured to disable IP masking.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on IP masking refer to the Geolocation and IP address handling section in the Azure Monitor documentation.",
                        "Url": "https://learn.microsoft.com/en-us/azure/azure-monitor/app/ip-collection?tabs=framework%2Cnodejs#storage-of-ip-address-data"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Azure",
                    "ProviderType": "CSP",
                    "ProviderAccountId": azSubId,
                    "AssetRegion": azRegion,
                    "AssetDetails": assetB64,
                    "AssetClass": "Management & Governance",
                    "AssetService": "Azure Application Insights",
                    "AssetComponent": "Component"
                },
                "Resources": [
                    {
                        "Type": "AzureApplicationInsightsComponent",
                        "Id": azSubId,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SubscriptionId": azSubId,
                                "ResourceGroupName": rgName,
                                "Region": azRegion,
                                "Name": appInsightCompName,
                                "Id": appInsightCompId
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
                        "ISO 27001:2013 A.16.1.7"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??