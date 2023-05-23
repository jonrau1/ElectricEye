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

API_ROOT = "https://graph.microsoft.com/v1.0"

def get_oauth_token(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_oauth_token")
    if response:
        return response

    # Retrieve an OAuth Token for the Microsoft Graph APIs
    tokenUrl = f"https://login.microsoftonline.com/{tenantId}/oauth2/token"
    resourceAppIdUri = "https://graph.microsoft.com"

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
    
def get_conditional_access_policies(cache, tenantId, clientId, clientSecret):
    
    response = cache.get("get_conditional_access_policies")
    if response:
        return response

    # Retrieve the Token from Cache
    headers = {
        "Authorization": f"Bearer {get_oauth_token(cache, tenantId, clientId, clientSecret)}"
    }

    r = requests.get(
        f"{API_ROOT}/identity/conditionalAccess/policies",
        headers=headers
    )

    if r.status_code != 200:
        raise r.reason
    else:
        cache["get_conditional_access_policies"] = r.json()["value"]
        return cache["get_conditional_access_policies"]
    
@registry.register_check("m365.conditionalaccess")
def m365_conditional_access_legacy_authentication_methods_block_policy_check(cache, awsAccountId, awsRegion, awsPartition, tenantId, clientId, clientSecret, tenantLocation):
    """
    [M365.DefenderRecommendations.1] Microsoft 365 Defender recommendations for MacOS Security Controls should be implemented
    """
    # ISO Time
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    policies = get_conditional_access_policies(cache, tenantId, clientId, clientSecret)

    # Find the Legacy Authentication Block (Exchange ActiveSync) Conditional Access Policy with a List Comprehension
    # First, check if "exchangeActiveSync" and "other" is in the Client App Types - this is what SecureScore wants
    # Then, ensure that the Policy is actually enabled
    # Then, ensure that the Policy includes ALL Applications within its scope
    # Then, ensure that the Policy includes ALL Users within its scope - there can be exclusions - but we'll ignore that
    # Finally, ensure that the Action (["grantControls"]["builtInControls"]) is set to Block - some policies may not
    # have "grantControls" so the "is not None" statement will skip that
    legacyAuthCaPolicy = [
        policy for policy in policies
        if ("exchangeActiveSync" and "other") in policy["conditions"]["clientAppTypes"]
        and policy["state"] == "enabled"
        and "All" in policy["conditions"]["applications"]["includeApplications"]
        and "All" in policy["conditions"]["users"]["includeUsers"]
        and policy["grantControls"] is not None
        and "block" in policy["grantControls"]["builtInControls"]
    ]

    if legacyAuthCaPolicy:
        assetJson = json.dumps(legacyAuthCaPolicy,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)
        displayName = legacyAuthCaPolicy[0]["displayName"]
        id = legacyAuthCaPolicy[0]["id"]
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/{id}"
        createdAt = str(legacyAuthCaPolicy[0]["id"])

    else:
        assetB64 = None
        displayName = ""
        id = ""
        resourceId = f"{tenantId}/identity/conditionalAccess/policies/blockLegacyAuthentication_placeholder"
        createdAt = ""