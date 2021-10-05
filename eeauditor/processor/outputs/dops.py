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
import boto3
import json
import os
import requests
from processor.outputs.output_base import ElectricEyeOutput


@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "dops"

    def __init__(self):
        ssm = boto3.client("ssm")

        try:
            dops_client_id_param = os.environ["DOPS_CLIENT_ID_PARAM"]
        except Exception as e:
            if str(e) == '"DOPS_CLIENT_ID_PARAM"':
                dops_client_id_param = "placeholder"
            else:
                print(e)
        try:
            dops_api_key_param = os.environ["DOPS_API_KEY_PARAM"]
        except Exception as e:
            if str(e) == '"DOPS_API_KEY_PARAM"':
                dops_api_key_param = "placeholder"
            else:
                print(e)

        if dops_api_key_param or dops_client_id_param == "placeholder":
            print('Either the DisruptOps API Keys were not provided, or the "placeholder" value was kept')
            exit(2)
        else:
            client_id_response = ssm.get_parameter(Name=dops_client_id_param, WithDecryption=True)
            api_key_response = ssm.get_parameter(Name=dops_api_key_param, WithDecryption=True)

            self.url = "https://collector.prod.disruptops.com/event"
            self.client_id = str(client_id_response["Parameter"]["Value"])
            self.api_key = str(api_key_response["Parameter"]["Value"])

    def write_findings(self, findings: list, **kwargs):
        print(f"Writing {len(findings)} results to DisruptOps")
        if self.client_id and self.api_key and self.url:
            for finding in findings:
                response = requests.post(
                    self.url, data=json.dumps(finding), auth=(self.client_id, self.api_key)
                )
        else:
            raise ValueError("Missing credentials for client_id or api_key")