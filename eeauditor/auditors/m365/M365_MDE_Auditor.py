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
def m365_mde_machine_unhealthy_sensor_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
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
                "GeneratorId": f"{tenantId}/oci-machine-secure-boot-check",
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
                "Id": f"{tenantId}/m365-defender-for-endpoint-machine-unhealthy-sensor-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"{tenantId}/oci-machine-secure-boot-check",
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