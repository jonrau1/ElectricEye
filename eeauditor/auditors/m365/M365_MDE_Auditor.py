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

import requests
import datetime
import base64
import json
from check_register import CheckRegister

registry = CheckRegister()

API_ROOT = "https://api-us.securitycenter.microsoft.com"

def get_oauth_token(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_oauth_token")
    if response:
        return response

    # Retrieve an OAuth Token for the Security Center APIs
    tokenUrl = f"https://login.microsoftonline.com/{tenantId}/oauth2/token"
    resourceAppIdUri = "https://api.securitycenter.microsoft.com"

    tokenData = {
        "client_id": clientId,
        "grant_type": "client_credentials",
        "resource" : resourceAppIdUri,
        "client_secret": clientSecret
    }

    r = requests.post(tokenUrl, data=tokenData)

    if r.status_code != 200:
        raise r.reason
    else:
        token = r.json()["access_token"]

        cache["get_oauth_token"] = token
        return cache["get_oauth_token"]
    
def get_mde_machines(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_mde_machines")
    if response:
        return response

    # Retrieve the Token from Cache
    token = get_oauth_token(cache, tenantId, clientId, clientSecret)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    r = requests.get(
        f"{API_ROOT}/api/machines",
        headers=headers
    )

    defenderMachines = []

    if r.status_code != 200:
        raise r.reason
    else:
        for machine in r.json()["value"]:
            # Ignore Inactive Machines (dead for 7 days) and manually excluded devices
            if machine["healthStatus"] == "Inactive" or machine["isExcluded"] is True:
                continue
            else:
                # Parse the ID for different calls
                machineId = machine["id"]
                # Retrieve data on Active Alerts
                machine["activeAlerts"] = get_alerts_by_machine(token, machineId)
                # Retrieve data on Explotiable Vulns
                machine["exploitableVulnerabilities"] = get_vulns_by_machine(token, machineId)

                defenderMachines.append(machine)

        cache["get_mde_machines"] = defenderMachines
        return cache["get_mde_machines"]
    
def get_alerts_by_machine(token, machineId):
    """
    This function returns a list of active Alerts for a specific Machine or returns an empty list if an API issues is encountered
    due to rate limit throttling, API issues, or the fact that the Machine does not have any Alerts or is not reporting
    """
    headers = {"Authorization": f"Bearer {token}"}

    alerts = requests.get(
        f"{API_ROOT}/api/machines/{machineId}/alerts",
        headers=headers
    )

    # Return empty lists when the Machine isn't found (404) or when there are not any alerts (empty ["value"])
    if alerts.status_code == 200:
        alertDoc = json.loads(alerts.text)
        if alertDoc["value"]:
            # Use a list comprehension to retrieve Alerts that haven't been resolved
            machineAlerts = [alert for alert in alertDoc["value"] if alert["status"] != "Resolved"]
            return machineAlerts
        else:
            return []
    else:
        return []
    
def get_vulns_by_machine(token, machineId):
    """
    This function returns a list of Vulnerabilities for a specified Machine given that the vulnerability is either reporting
    exploitable by Microsoft Security Threat Intelligence Center (MSTIC) or matches a value in CISA's KEV Catalog. Will return 
    an empty list if an API issues is encountered due to rate limit throttling, API issues, or the fact that the Machine does
    not have any Vulnerabilities at all, no explotiable Vulnerabilities, or is not reporting
    """
    headers = {"Authorization": f"Bearer {token}"}

    vulns = requests.get(
        f"{API_ROOT}/api/machines/{machineId}/vulnerabilities",
        headers=headers
    )

    # Get CVEs reported in CISA's KEV DB
    kevCves = get_cisa_kev()

    # Return empty lists when the Machine isn't found (404) or when there are not any alerts (empty ["value"])
    if vulns.status_code == 200:
        vulnDoc = json.loads(vulns.text)
        if vulnDoc["value"]:
            # Use a list comprehension to retrieve Vulns that report exploitable by Microsoft or are in the CISA KEV
            machineVulns = [vuln for vuln in vulnDoc["value"] if vuln["publicExploit"] is True or vuln["id"] in kevCves]
            return machineVulns
        else:
            return []
    else:
        return []

# Called by get_vulns_by_machine()
def get_cisa_kev():
    """
    Retrieves the U.S. CISA's Known Exploitable Vulnerabilities (KEV) Catalog and returns a list of CVE ID's
    """

    rawKev = json.loads(
        requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        ).text
    )["vulnerabilities"]

    kevCves = [cve["cveID"] for cve in rawKev]

    return kevCves

@registry.register_check("m365.mde")
def m365_mde_machine_unhealthy_sensor_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.MDE.1] Microsoft Defender for Endpoint protected devices with unhealthy sensors should be investigated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for machine in get_mde_machines(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(machine,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        machineId = machine["id"]
        computerDnsName = machine["computerDnsName"]
        firstSeen = str(machine["firstSeen"])
        lastSeen = str(machine["lastSeen"])
        osPlatform = str(machine["osPlatform"])

        # Begin finding evaluation
        if machine["healthStatus"] == "NoSensorData":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-unhealthy-sensor-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-unhealthy-sensor-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[M365.MDE.1] Microsoft Defender for Endpoint protected devices with unhealthy sensors should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does have an unhealthy sensor. Devices can be categorized as misconfigured or inactive are flagged for varying causes, An inactive device isn't necessarily flagged because of an issue. The following actions taken on a device can cause a device to be categorized as inactive: it is not in use, it is renamed, it was offboarded or is not sending signals. Any device that isn't in use for more than seven days retains 'Inactive' status in the portal and API. A new device entity is generated in Microsoft 365 Defender for reinstalled or renamed devices. If the device was offboarded, it still appears in devices list. After seven days, the device health state should change to inactive. If the device isn't sending any signals to any Microsoft Defender for Endpoint channels for more than seven days for any reason, a device can be considered inactive; this includes conditions that fall under misconfigured devices classification. Ensure the device has Internet connection and verify client connectivity to Microsoft Defender for Endpoint service URLs and that Microsoft Defender Antivirus isn't disabled by policy. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on troubleshooting unhealthy sensors for Defender for Endpoint refer to the Fix unhealthy sensors in Microsoft Defender for Endpoint section of the Microsoft Defender for Endpoint documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/fix-unhealthy-sensors?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
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
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-unhealthy-sensor-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-unhealthy-sensor-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.1] Microsoft Defender for Endpoint protected devices with unhealthy sensors should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does not have an unhealthy sensor.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on troubleshooting unhealthy sensors for Defender for Endpoint refer to the Fix unhealthy sensors in Microsoft Defender for Endpoint section of the Microsoft Defender for Endpoint documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/fix-unhealthy-sensors?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
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

@registry.register_check("m365.mde")
def m365_mde_machine_high_risk_score_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.MDE.2] Microsoft Defender for Endpoint protected devices with a High risk level should be investigated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for machine in get_mde_machines(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(machine,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        machineId = machine["id"]
        computerDnsName = machine["computerDnsName"]
        firstSeen = str(machine["firstSeen"])
        lastSeen = str(machine["lastSeen"])
        osPlatform = str(machine["osPlatform"])

        # Begin finding evaluation
        if machine["riskScore"] == "High":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-high-risk-level-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-high-risk-level-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[M365.MDE.2] Microsoft Defender for Endpoint protected devices with a High risk level should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does have a High Risk level. The risk level reflects the overall risk assessment of the device based on combination of factors, including the types and severity of active alerts on the device. Resolving active alerts, approving remediation activities, and suppressing subsequent alerts can lower the risk level. The risk level can influence enforcement of conditional access and other security policies on Microsoft Intune and other connected solutions. Use a device compliance policy to set the level of risk you want to allow. Risk levels are reported by Microsoft Defender for Endpoint, devices that exceed the allowed risk level are identified as noncompliant. Open alerts that correspond to malicious or suspicious activity are the main drivers for a risk level of 'High'. Ensure that alerts are investigated and closed as soon as possible or as soon as your SLAs dictate. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on risk levels and setting up Intune compliance policies refer to the Enforce compliance for Microsoft Defender for Endpoint with Conditional Access in Intune section of the Microsoft Intune documentation.",
                        "Url": "https://learn.microsoft.com/en-us/mem/intune/protect/advanced-threat-protection"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
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
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-high-risk-level-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-high-risk-level-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.2] Microsoft Defender for Endpoint protected devices with a High risk level should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does not have a High Risk level. While the risk level may not be reporting as High, review your devices that are also reporting Low and Medium for any threats or misconfigurations that can directly impact your environment.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on risk levels and setting up Intune compliance policies refer to the Enforce compliance for Microsoft Defender for Endpoint with Conditional Access in Intune section of the Microsoft Intune documentation.",
                        "Url": "https://learn.microsoft.com/en-us/mem/intune/protect/advanced-threat-protection"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
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

@registry.register_check("m365.mde")
def m365_mde_machine_high_exposure_score_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.MDE.3] Microsoft Defender for Endpoint protected devices with a High exposure score should be investigated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for machine in get_mde_machines(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(machine,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        machineId = machine["id"]
        computerDnsName = machine["computerDnsName"]
        firstSeen = str(machine["firstSeen"])
        lastSeen = str(machine["lastSeen"])
        osPlatform = str(machine["osPlatform"])

        # Begin finding evaluation
        if machine["exposureLevel"] == "High":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-high-exposure-level-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-high-exposure-level-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[M365.MDE.3] Microsoft Defender for Endpoint protected devices with a High exposure score should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does have a High exposure score. Your exposure score is visible in the Defender Vulnerability Management dashboard in the Microsoft 365 Defender portal. It reflects how vulnerable your organization is to cybersecurity threats. Low exposure score means your devices are less vulnerable to exploitation. When software weaknesses are identified, they are transformed into recommendations and prioritized based on risk to the organization. By remediating vulnerabilities with security recommendations prioritized to reduce your exposure score, you can reduce your overall vulnerability exposure. The security recommendations page will open with a list of security recommendations prioritized by the potential impact on your exposure score. The higher the impact on lowering your exposure by implementing a recommendation, the less vulnerable you will be to exploitation. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on exposure scores and remediation logic refer to the Exposure score in Defender Vulnerability Management section of the Microsoft Defender Vulnerability Management documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-exposure-score?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-high-exposure-level-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-high-exposure-level-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.3] Microsoft Defender for Endpoint protected devices with a High exposure score should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does not have a High exposure score. While the exposure score may not be reporting as High, review your devices that are also reporting Low and Medium for any threats or misconfigurations that can directly impact your environment.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on exposure scores and remediation logic refer to the Exposure score in Defender Vulnerability Management section of the Microsoft Defender Vulnerability Management documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-exposure-score?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.1",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.6.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("m365.mde")
def m365_mde_machine_exploitable_vulns_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.MDE.4] Microsoft Defender for Endpoint protected devices with known exploitable vulnerabilities should be immediately remediated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for machine in get_mde_machines(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(machine,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        machineId = machine["id"]
        computerDnsName = machine["computerDnsName"]
        firstSeen = str(machine["firstSeen"])
        lastSeen = str(machine["lastSeen"])
        osPlatform = str(machine["osPlatform"])

        # Begin finding evaluation
        if machine["exploitableVulnerabilities"]:
            # Get the CVEs
            exploitableCves = [vuln["id"] for vuln in machine["exploitableVulnerabilities"]]
            cveSentence = ", ".join(exploitableCves)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-exploitable-vulns-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-exploitable-vulns-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "CRITICAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.4] Microsoft Defender for Endpoint protected devices with known exploitable vulnerabilities should be immediately remediated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} has at least one active and exploitable vulnerability and should be immediately remediated. The following CVEs are exploitable: {cveSentence}. In MDE, the threat insights icon is highlighted if there are associated exploits in the vulnerability found in your organization. Hovering over the icon shows whether the threat is a part of an exploit kit, or connected to specific advanced persistent campaigns or activity groups. When available, there's a link to a Threat Analytics report with zero-day exploitation news, disclosures, or related security advisories. ElectricEye uses the Microsoft Security Threat Intelligence Center (MSTIC) exploitation enrichment for vulnerabilities as well as the CISA KEV catalog to determine if a CVE is exploitable. Exploitable vulnerabilities that are public have a higher chance of being actively targeted by adversaries and can cause irreperable harm to your organization. These vulnerabilities should be remediated or otherwise countered as soon as possible. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on vulnerability information and enrichments refer to the Vulnerabilities in my organization section of the Microsoft Defender Vulnerability Management documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-weaknesses?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST CSF V1.1 ID.RA-2",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 PM-15",
                        "NIST SP 800-53 Rev. 4 PM-16",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.6.1.4",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-exploitable-vulns-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-exploitable-vulns-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.4] Microsoft Defender for Endpoint protected devices with known exploitable vulnerabilities should be immediately remediated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does not have an exploitable vulnerability. The device may still have other vulnerabilities that should be remediated as per your internal Standard Operating Procedures (SOPs) regardless if they are exploitable or not.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on vulnerability information and enrichments refer to the Vulnerabilities in my organization section of the Microsoft Defender Vulnerability Management documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-vulnerability-management/tvm-weaknesses?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.CM-8",
                        "NIST CSF V1.1 ID.RA-1",
                        "NIST CSF V1.1 ID.RA-2",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CA-8",
                        "NIST SP 800-53 Rev. 4 PM-15",
                        "NIST SP 800-53 Rev. 4 PM-16",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 RA-5",
                        "NIST SP 800-53 Rev. 4 SA-5",
                        "NIST SP 800-53 Rev. 4 SA-11",
                        "NIST SP 800-53 Rev. 4 SI-2",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "NIST SP 800-53 Rev. 4 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.1",
                        "ISO 27001:2013 A.6.1.4",
                        "ISO 27001:2013 A.12.6.1",
                        "ISO 27001:2013 A.12.6.4",
                        "ISO 27001:2013 A.18.2.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("m365.mde")
def m365_mde_machine_active_alerts_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, tenantId: str, clientId: str, clientSecret: str, tenantLocation: str) -> dict:
    """
    [M365.MDE.5] Microsoft Defender for Endpoint protected devices with active Alerts should be investigated
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for machine in get_mde_machines(cache, tenantId, clientId, clientSecret):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(machine,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        machineId = machine["id"]
        computerDnsName = machine["computerDnsName"]
        firstSeen = str(machine["firstSeen"])
        lastSeen = str(machine["lastSeen"])
        osPlatform = str(machine["osPlatform"])

        # Begin finding evaluation
        if machine["activeAlerts"]:
            # Get the CVEs
            activeAlerts = [alert["title"] for alert in machine["activeAlerts"]]
            alertSentence = ", ".join(activeAlerts)
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-active-alerts-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-active-alerts-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[M365.MDE.5] Microsoft Defender for Endpoint protected devices with active Alerts should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} has at least one active Alert and should be investigated. The following Alert titles are not resolved: {alertSentence}. Defender for Endpoint notifies you of possible malicious events, attributes, and contextual information through alerts. A summary of new alerts is displayed and you can access all alerts in the Alerts queue. There might be scenarios where you need to suppress alerts from appearing in Microsoft 365 Defender. Defender for Endpoint lets you create suppression rules for specific alerts that are known to be innocuous such as known tools or processes in your organization. You can choose not to set a classification, or specify whether an alert is a true alert or a false alert. It's important to provide the classification of true positive/false positive. This classification is used to monitor alert quality, and make alerts more accurate. The 'determination' field defines additional fidelity for a 'true positive' classification. ElectricEye will pull in Alerts per Device (machine) using the Security Graph API that are not reporting as resolved. Depending on your license and integrations, MDE may automatically close alerts or may create alerts even if an action was prevented by EDR, Defender AV, or Network Protection. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on alert information, invesigation, and suppression refer to theManage Microsoft Defender for Endpoint alerts section of the Microsoft Defender for Endpoint documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-alerts?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
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
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-active-alerts-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/m365-defender-for-endpoint-machine-active-alerts-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[M365.MDE.5] Microsoft Defender for Endpoint protected devices with active Alerts should be investigated",
                "Description": f"Microsoft Defender for Endpoint protected device {machineId} in M365 Tenant {tenantId} does not have any active Alerts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on alert information, invesigation, and suppression refer to theManage Microsoft Defender for Endpoint alerts section of the Microsoft Defender for Endpoint documentation.",
                        "Url": "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-alerts?view=o365-worldwide"
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "M365",
                    "ProviderType": "SaaS",
                    "ProviderAccountId": tenantId,
                    "AssetRegion": tenantLocation,
                    "AssetDetails": assetB64,
                    "AssetClass": "Security Services",
                    "AssetService": "Microsoft 365 Defender",
                    "AssetComponent": "Machine"
                },
                "Resources": [
                    {
                        "Type": "M365DefenderForEndpointMachine",
                        "Id": f"{tenantId}/{machineId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "TenantId": tenantId,
                                "Id": machineId,
                                "ComputeDnsName": computerDnsName,
                                "FirstSeen": firstSeen,
                                "LastSeen": lastSeen,
                                "OsPlatform": osPlatform
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 DE.AE-2",
                        "NIST CSF V1.1 DE.AE-4",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 RA-3",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC7.2",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??