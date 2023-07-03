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

def get_salesforce_transaction_security_policies(cache: dict, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str):
    response = cache.get("get_salesforce_transaction_security_policies")
    if response:
        return response
    
    token = retrieve_oauth_token(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    accessToken = token["access_token"]
    instanceUrl = token["instance_url"]

    headers = {
        "Authorization": f"Bearer {accessToken}",
        "Content-Type": "application/json"
    }

    # Query out all possible values for TransactionSecurityPolicy
    url = f"{instanceUrl}/services/data/{SFDC_API_VERSION}/query/"
    query = """
    SELECT ActionConfig, ApexPolicyId, BlockMessage, CustomEmailContent, Description, DeveloperName, EventName, EventType, ExecutionUserId, MasterLabel, NamespacePrefix, ResourceName, State, Type 
    FROM TransactionSecurityPolicy
    """
    tspQuery = requests.get(url, headers=headers, params={"q": query})
    if tspQuery.status_code != 200:
        print("Failed to retrieve Transaction Security Policies from Salesforce! Exiting.")
        raise tspQuery.reason
    # Use a list comprehension to re-sort the data
    allTsps = [tpolicy for tpolicy in tspQuery.json()["records"]]

    # Return a tuple of the list of TSPs and the Instance URL which is used as the GUID for the instance
    payload = (allTsps, instanceUrl)

    cache["get_salesforce_transaction_security_policies"] = payload
    return cache["get_salesforce_transaction_security_policies"]

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
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,
            "Title": "[Salesforce.ThreatDetection.1] Salesforce threat detection events for session hijacking should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} has active threat detection events for session hijacking open that should be investigated. Session Hijacking is a customer-focused attack where attackers try to steal information from using a client's access to a web application. In our case, this application is Salesforce. When a client successfully authenticates with Salesforce, they receive a session token. The attacker tries to hijack the client's session by obtaining their session token. The Real-Time Event Monitoring object SessionHijackingEvent addresses the “Man In The Browser” attack (MiTB), a type of session hijacking attack. In a MiTB attack, the attacker compromises the client's web application by first planting a virus like a Trojan proxy. The virus then embeds itself in the client's browser. And when the client accesses a web application such as Salesforce, the virus manipulates pages, collects sensitive information shared between client and Salesforce, and steals information. These types of attacks are difficult for the client to detect. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating session hijacking events refer to the Investigate Session Hijacking section of the Salesforce Help Center.",
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
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
                    "Text": "For more information on investigating session hijacking events refer to the Investigate Session Hijacking section of the Salesforce Help Center.",
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
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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

@registry.register_check("salesforce.threatdetection")
def salesforce_open_credential_stuffing_threat_detection_results_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.2] Salesforce threat detection events for credential stuffing should be investigated and responded to
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Query
    query = """
    SELECT UserId, EventDate, Summary 
    FROM CredentialStuffingEventStore
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
            "Id": f"salesforce/{payload[1]}/threatdetection/credentialstuffing/salesforce-open-credentialstuffing-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/credentialstuffing/salesforce-open-credentialstuffing-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "HIGH"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.2] Salesforce threat detection events for credential stuffing should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} has active threat detection events for credential stuffing open that should be investigated. Credential stuffing is a type of cyber attack that uses stolen account credentials. It's also known as “password spraying” or “credential spills”. Attackers obtain large numbers of usernames and passwords through data breaches or other types of cyber attacks. They then use these credentials to gain unauthorized access to user accounts through large-scale automated login requests against a web application such as Salesforce. Salesforce identifies a credential stuffing attack using a two-step process. First, it detects if a credential stuffing attack is taking place by analyzing the login traffic. In particular, we look for attackers who stuff multiple credentials in the same end-point or stuff the same user accounts by enumerating multiple passwords. Next we check the ratio of successful versus failed login traffic volume. If the volume exceeds a certain threshold, we use more fingerprint details to identify the affected user's profile. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating credential stuffing events refer to the Investigate Credential Stuffing section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_credstuff_review.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/credentialstuffing",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
            "Id": f"salesforce/{payload[1]}/threatdetection/credentialstuffing/salesforce-open-credentialstuffing-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/credentialstuffing/salesforce-open-credentialstuffing-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.2] Salesforce threat detection events for credential stuffing should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} does not have active threat detection events for credential stuffing open that should be investigated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating credential stuffing events refer to the Investigate Credential Stuffing section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_credstuff_review.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/credentialstuffing",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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

@registry.register_check("salesforce.threatdetection")
def salesforce_open_report_anomaly_threat_detection_results_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.3] Salesforce threat detection events for report anomaly should be investigated and responded to
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Query
    query = """
    SELECT Score, UserId, EventDate, Report, SecurityEventData, Summary
    FROM ReportAnomalyEventStore
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
            "Id": f"salesforce/{payload[1]}/threatdetection/reportanomaly/salesforce-open-reportanomaly-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/reportanomaly/salesforce-open-reportanomaly-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.3] Salesforce threat detection events for report anomaly should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} has active threat detection events for report anomaly open that should be investigated. An anomaly is any user activity that is sufficiently different from the historical activity of the same user. We use the metadata in Salesforce Core application logs about report generation and surrounding activities to build a baseline model of the historical activity. We then compare any new report generation activity against this baseline to determine if the new activity is sufficiently different to be called an anomaly. We don't look at the actual data that a user interacts with— we look at how the user interacts with the data. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating report anomalies events refer to the Investigate Report Anomalies section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_detection_review.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/reportanomaly",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
            "Id": f"salesforce/{payload[1]}/threatdetection/reportanomaly/salesforce-open-reportanomaly-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/reportanomaly/salesforce-open-reportanomaly-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.3] Salesforce threat detection events for report anomaly should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} does not have active threat detection events for report anomaly open that should be investigated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating report anomalies events refer to the Investigate Report Anomalies section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_detection_review.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/reportanomaly",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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

@registry.register_check("salesforce.threatdetection")
def salesforce_open_api_anomaly_threat_detection_results_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.4] Salesforce threat detection events for API anomaly should be investigated and responded to
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Query
    query = """
    SELECT Score, UserId, EventDate, SecurityEventData, Summary
    FROM ApiAnomalyEventStore
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
            "Id": f"salesforce/{payload[1]}/threatdetection/apianomaly/salesforce-open-apianomaly-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/apianomaly/salesforce-open-apianomaly-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.4] Salesforce threat detection events for API anomaly should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} has active threat detection events for API anomaly open that should be investigated. An anomaly is any user activity that is sufficiently different from the historical activity of the same user. We use the metadata in Salesforce Core application logs about API generation and surrounding activities to build a baseline model of the historical activity. We then compare any new API generation activity against this baseline to determine if the new activity is sufficiently different to be called an anomaly. We don't look at the actual data that a user interacts with— we look at how the user interacts with the data. It's often necessary to further investigate an API request anomaly to either determine if a data breach occurred or to rule it out as benign. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating API anomalies events refer to the Investigate API Request Anomalies section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_detection_investigate_api_anomaly.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/apianomaly",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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
            "Id": f"salesforce/{payload[1]}/threatdetection/apianomaly/salesforce-open-apianomaly-alerts-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/threatdetection/apianomaly/salesforce-open-apianomaly-alerts-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,   
            "Title": "[Salesforce.ThreatDetection.4] Salesforce threat detection events for API anomaly should be investigated and responded to",
            "Description": f"Salesforce instance {payload[1]} does not have active threat detection events for API anomaly open that should be investigated.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on investigating API anomalies events refer to the Investigate API Request Anomalies section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.real_time_em_threat_detection_investigate_api_anomaly.htm&type=5"
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
                    "Id": f"{payload[1]}/threatdetection/apianomaly",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
                        }
                    }
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

@registry.register_check("salesforce.threatdetection")
def salesforce_transaction_security_policies_in_use_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.5] Salesforce instances should implement transaction security policies
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_transaction_security_policies(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    if not payload[0]:
        assetB64 = None
        tspInUse = False
    else:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(payload[0],default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        tspInUse = True
    # this is a failing check
    if tspInUse is False:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/salesforce-tsp-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/salesforce-tsp-in-use-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Salesforce.ThreatDetection.5] Salesforce instances should implement transaction security policies",
            "Description": f"Salesforce instance {payload[1]} does not implement transaction security policies. Enhanced Transaction Security is a framework that intercepts real-time events and applies appropriate actions to monitor and control user activity. Each transaction security policy has conditions that evaluate events and the real-time actions that are triggered after those conditions are met. The actions are Block, Multi-Factor Authentication, and Notifications. Before you build your policies, understand the available event types, policy conditions, and common use cases. Enhanced Transaction Security is included in Real-Time Event Monitoring. Condition Builder is a Setup feature that allows you to build policies with clicks, not code. Policies monitor events, which are categories of user activity built on objects in the SOAP, REST, and Bulk APIs. When you build your policy using Condition Builder, you choose which fields on these objects you want to monitor for customer activity. Refer to the remediation instructions if this configuration is not intended.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on uses for and implementation of transaction security policies refer to the Enhanced Transaction Security section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_policy_types.htm&type=5"
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
                "AssetService": "Salesforce Enhanced Transaction Security",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "SalesforceTransactionSecurityPolicy",
                    "Id": f"{payload[1]}/TransactionSecurityPolicy",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
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
            "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/salesforce-tsp-in-use-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/salesforce-tsp-in-use-check",
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Salesforce.ThreatDetection.5] Salesforce instances should implement transaction security policies",
            "Description": f"Salesforce instance {payload[1]} does implement transaction security policies.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on uses for and implementation of transaction security policies refer to the Enhanced Transaction Security section of the Salesforce Help Center.",
                    "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_policy_types.htm&type=5"
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
                "AssetService": "Salesforce Enhanced Transaction Security",
                "AssetComponent": "Policy"
            },
            "Resources": [
                {
                    "Type": "SalesforceTransactionSecurityPolicy",
                    "Id": f"{payload[1]}/TransactionSecurityPolicy",
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "SalesforceInstanceUrl": payload[1]
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

@registry.register_check("salesforce.threatdetection")
def salesforce_transaction_security_policy_alerting_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.6] Salesforce transaction security policies should be configured to send alerts
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_transaction_security_policies(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for tsp in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(tsp,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        tspId = tsp["attributes"]["url"].split("/")[6]
        tspName = tsp["MasterLabel"]
        # Use a series of list comprehensions to check if there are any Users that will be alerted and if at least one
        # form of alerting (In-App and/or Email) is configured. If either list is empty there is not alerting configured
        actionConfig = (json.loads(tsp["ActionConfig"]))
        if actionConfig["userNotificationList"]:
            alertingRule = [config for config in actionConfig["userNotificationList"] if config["emailNotification"] or config["inAppNotification"] is True]
            if alertingRule:
                tspSendsAlerts = True
            else:
                tspSendsAlerts = False
        else:
            tspSendsAlerts = False
        # this is a failing check
        if tspSendsAlerts is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-alerting-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-alerting-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "LOW"},
                "Confidence": 99,
                "Title": "[Salesforce.ThreatDetection.6] Salesforce transaction security policies should be configured to send alerts",
                "Description": f"Salesforce transaction security policy {tspName} in instance {payload[1]} is not configured to send alerts. This check fails if there is not at least one User within the Notification List that has either in-app or email notifications enabled. When a real-time event triggers a transaction security policy, you can block a user or enforce multi-factor authentication (MFA). You can also optionally receive in-app or email notifications of the event. You can send two kinds of email notifications when a policy is triggered: default email messages and custom email messages. Both use the subject Transaction Security Alert. Additionally, you can configure In-app notifications which list the policy that was triggered. Notifications aren't available in Classic. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on actions and notifications against transaction security policies refer to the Enhanced Transaction Security Actions and Notifications section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_actions_notifs.htm&type=5"
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
                    "AssetService": "Salesforce Enhanced Transaction Security",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SalesforceTransactionSecurityPolicy",
                        "Id": f"{payload[1]}/TransactionSecurityPolicy/{tspId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "MasterLabel": tspName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-7",
                        "NIST CSF V1.1 RS.AN-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PL-2",
                        "NIST SP 800-53 Rev. 4 PM-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC4.2",
                        "AICPA TSC CC5.1",
                        "AICPA TSC CC5.3",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.16.1.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-alerting-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-alerting-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.ThreatDetection.6] Salesforce transaction security policies should be configured to send alerts",
                "Description": f"Salesforce transaction security policy {tspName} in instance {payload[1]} is configured to send alerts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on actions and notifications against transaction security policies refer to the Enhanced Transaction Security Actions and Notifications section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_actions_notifs.htm&type=5"
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
                    "AssetService": "Salesforce Enhanced Transaction Security",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SalesforceTransactionSecurityPolicy",
                        "Id": f"{payload[1]}/TransactionSecurityPolicy/{tspId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "MasterLabel": tspName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-7",
                        "NIST CSF V1.1 RS.AN-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PL-2",
                        "NIST SP 800-53 Rev. 4 PM-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC4.2",
                        "AICPA TSC CC5.1",
                        "AICPA TSC CC5.3",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.16.1.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("salesforce.threatdetection")
def salesforce_transaction_security_policy_response_action_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, salesforceAppClientId: str, salesforceAppClientSecret: str, salesforceApiUsername: str, salesforceApiPassword: str, salesforceUserSecurityToken: str, salesforceInstanceLocation: str):
    """
    [Salesforce.ThreatDetection.7] Salesforce transaction security policies should be configured to enforce a blocking or MFA-challenge action
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # Retrieve cache
    payload = get_salesforce_transaction_security_policies(cache, salesforceAppClientId, salesforceAppClientSecret, salesforceApiUsername, salesforceApiPassword, salesforceUserSecurityToken)
    # Check if there any policies at all
    for tsp in payload[0]:
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(tsp,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        tspId = tsp["attributes"]["url"].split("/")[6]
        tspName = tsp["MasterLabel"]
        actionConfig = (json.loads(tsp["ActionConfig"]))
        # check if at least one of the four possible actions for TSPs is configured, if so, this is a passing check
        if (
            actionConfig["blockAction"] or
            actionConfig["twoFaAction"] or
            actionConfig["endSessionAction"] or
            actionConfig["freezeAction"]
        ) is True:
            tspTakesAction = True
        else:
            tspTakesAction = False
        # this is a failing check
        if tspTakesAction is False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-actions-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-actions-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Salesforce.ThreatDetection.7] Salesforce transaction security policies should be configured to enforce a blocking or MFA-challenge action",
                "Description": f"Salesforce transaction security policy {tspName} in instance {payload[1]} is not configured to enforce a blocking or MFA-challenge action. When a real-time event triggers a transaction security policy, you can block a user or enforce multi-factor authentication (MFA). Block does not let the user complete the request. For example, if a ReportEvent policy with a block action triggers during a report view, the user sees a message explaining the action. You can also customize the block message when you create your policy. Each custom message can be up to 1000 characters, and you can only customize messages for ApiEvent, ListViewEvent, and ReportEvent policies. Custom block messages aren't translated. MFA will prompt the user to confirm their identity with an additional verification method, such as the Salesforce Authenticator app, when they log in. In situations where you can't use multi-factor authentication (for instance, during an API query), this action changes to a block action. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on actions and notifications against transaction security policies refer to the Enhanced Transaction Security Actions and Notifications section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_actions_notifs.htm&type=5"
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
                    "AssetService": "Salesforce Enhanced Transaction Security",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SalesforceTransactionSecurityPolicy",
                        "Id": f"{payload[1]}/TransactionSecurityPolicy/{tspId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "MasterLabel": tspName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-7",
                        "NIST CSF V1.1 RS.AN-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PL-2",
                        "NIST SP 800-53 Rev. 4 PM-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC4.2",
                        "AICPA TSC CC5.1",
                        "AICPA TSC CC5.3",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.16.1.5"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-actions-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"salesforce/{payload[1]}/transactionsecuritypolicy/{tspId}/salesforce-tsp-actions-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Salesforce.ThreatDetection.7] Salesforce transaction security policies should be configured to enforce a blocking or MFA-challenge action",
                "Description": f"Salesforce transaction security policy {tspName} in instance {payload[1]} is configured to enforce a blocking or MFA-challenge action.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on actions and notifications against transaction security policies refer to the Enhanced Transaction Security Actions and Notifications section of the Salesforce Help Center.",
                        "Url": "https://help.salesforce.com/s/articleView?id=sf.enhanced_transaction_security_actions_notifs.htm&type=5"
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
                    "AssetService": "Salesforce Enhanced Transaction Security",
                    "AssetComponent": "Policy"
                },
                "Resources": [
                    {
                        "Type": "SalesforceTransactionSecurityPolicy",
                        "Id": f"{payload[1]}/TransactionSecurityPolicy/{tspId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "SalesforceInstanceUrl": payload[1],
                                "MasterLabel": tspName
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF V1.1 PR.IP-7",
                        "NIST CSF V1.1 RS.AN-1",
                        "NIST SP 800-53 Rev. 4 CA-2",
                        "NIST SP 800-53 Rev. 4 CA-7",
                        "NIST SP 800-53 Rev. 4 CP-2",
                        "NIST SP 800-53 Rev. 4 IR-8",
                        "NIST SP 800-53 Rev. 4 PL-2",
                        "NIST SP 800-53 Rev. 4 PM-6",
                        "NIST SP 800-53 Rev. 4 AU-6",
                        "NIST SP 800-53 Rev. 4 IR-4",
                        "NIST SP 800-53 Rev. 4 IR-5",
                        "NIST SP 800-53 Rev. 4 PE-6",
                        "NIST SP 800-53 Rev. 4 SI-4",
                        "AICPA TSC CC4.2",
                        "AICPA TSC CC5.1",
                        "AICPA TSC CC5.3",
                        "AICPA TSC CC7.3",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.12.4.3",
                        "ISO 27001:2013 A.16.1.5"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

## END ??