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