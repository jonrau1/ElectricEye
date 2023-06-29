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

from check_register import CheckRegister
import requests
import os
import datetime
import base64
import json

registry = CheckRegister()

SFDC_API_VERSION = os.environ["SFDC_API_VERSION"]

def retrieve_oauth_token(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str):
    """
    Creates a Salesforce OAuth config & returns the access token
    """
    
    response = cache.get("retrieve_oauth_token")
    if response:
        return response

    # Obtain access token using username-password flow
    data = {
        "grant_type": "password",
        "client_id": salesforceAppClientId,
        "client_secret": salesforceAppClientSecret,
        "username": salesforceApiUsername,
        "password": f"{salesforceApiPassword}{salesforceUserSecurityToken}"
    }

    # Retrieve the Token
    token = requests.post(
        "https://login.salesforce.com/services/oauth2/token",
        data=data
    ).json()

    # Parse the Token and the URL of the Instance
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]
    payload = {"access_token": accessToken, "instance_url": instanceUrl}

    cache["retrieve_oauth_token"] = payload
    return cache["retrieve_oauth_token"]

def submit_salesforce_query(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, query: str):
    """
    Returns the results of a submitted query from the Query API
    """

    # We do not use cache retrieval yet as the queries are all different, we need the cache present for the oauth token
    
    token = retrieve_oauth_token(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]

    headers = {
        "Authorization": f"Bearer {accessToken}",
        "Content-Type": "application/json"
    }

    # First call will use a Query to retrieve relevant user data
    url = f"{instanceUrl}/services/data/{SFDC_API_VERSION}/query/"

    queryResult = requests.get(url, headers=headers, params={"q": query})
    if queryResult.status_code != 200:
        print("Failed to submit Threat Detection related query! Exiting.")
        raise queryResult.reason
    # Use a list comprehension to flatten the data and return it
    result =  [record for record in queryResult.json()["records"]]

    # Return a tuple of the list from the query result and the Instance URL which is used as the GUID for the instance
    payload = (result, instanceUrl)

    return payload

@registry.register_check("salesforce.threatdetection")
def salesforce_open_session_hijacking_threat_detection_results_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.1] Salesforce threat detection events for session hijacking should be investigated and responded to
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Query
    query = """
    SELECT Score, UserId, EventDate, SecurityEventData, Summary 
    FROM SessionHijackingEventStore
    """
    # Retrieve the query result
    payload = submit_salesforce_query(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken, query)
    # Having results is a failing check
    if payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(payload[0],default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"salesforce/{payload[1]}/threatdetection/sessionhijacking/salesforce-open-sessionhijacking-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/sessionhijacking/salesforce-open-sessionhijacking-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Salesforce.ThreatDetection.1] Salesforce threat detection events for session hijacking should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} has active threat detection events for session hijacking open that should be investigated. Session Hijacking is a customer-focused attack where attackers try to steal information from using a client's access to a web application. In our case, this application is Salesforce. When a client successfully authenticates with Salesforce, they receive a session token. The attacker tries to hijack the client's session by obtaining their session token. The Real-Time Event Monitoring object SessionHijackingEvent addresses the “Man In The Browser” attack (MiTB), a type of session hijacking attack. In a MiTB attack, the attacker compromises the client's web application by first planting a virus like a Trojan proxy. The virus then embeds itself in the client's browser. And when the client accesses a web application such as Salesforce, the virus manipulates pages, collects sensitive information shared between client and Salesforce, and steals information. These types of attacks are difficult for the client to detect. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigated session hijacking events refer to the Investigate Session Hijacking section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_session_review.htm&type=5"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Salesforce",
                "ProviderType": "SaaS",
                "ProviderAccountId": payload[1],
                "AssetRegion": salesforceInstanceLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Salesforce Threat Detection",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "SalesforceThreatDetectionEvent",
                    "Id": f"{payload[1]}/threatdetection/sessionhijacking",
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "AICPA TSC CC7.2",
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
        assetB64 = None
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"salesforce/{payload[1]}/threatdetection/sessionhijacking/salesforce-open-sessionhijacking-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/sessionhijacking/salesforce-open-sessionhijacking-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Salesforce.ThreatDetection.1] Salesforce threat detection events for session hijacking should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} does not have active threat detection events for session hijacking open that should be investigated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigated session hijacking events refer to the Investigate Session Hijacking section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_session_review.htm&type=5"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Salesforce",
                "ProviderType": "SaaS",
                "ProviderAccountId": payload[1],
                "AssetRegion": salesforceInstanceLocation,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "Salesforce Threat Detection",
                "AssetComponent": "Event"
            },
            "Resources": [
                {
                    "Type": "SalesforceThreatDetectionEvent",
                    "Id": f"{payload[1]}/threatdetection/sessionhijacking",
                    "Partition": awsPartition,
                    "Region": awsRegion
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
                    "AICPA TSC CC7.2",
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