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

import tomli
import boto3
import sys
import json
import os
import requests
from time import sleep
from botocore.exceptions import ClientError
from processor.outputs.output_base import ElectricEyeOutput

# Boto3 Clients
ssm = boto3.client("ssm")
asm = boto3.client("secretsmanager")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

@ElectricEyeOutput
class DopsProvider(object):
    __provider__ = "firemon_cloud_defense"

    def __init__(self):
        print("Preparing Firemon Cloud Defense (DisruptOps) credentials.")

        # Get the absolute path of the current directory
        currentDir = os.path.abspath(os.path.dirname(__file__))
        # Go two directories back to /eeauditor/
        twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

        # TOML is located in /eeauditor/ directory
        tomlFile = f"{twoBack}/external_providers.toml"
        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Parse from [global] to determine credential location of PostgreSQL Password
        if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
            print(f"Invalid option for [global.credentials_location]. Must be one of {str(CREDENTIALS_LOCATION_CHOICES)}.")
            sys.exit(2)
        self.credentials_location = data["global"]["credentials_location"]

        # Variable for the entire [outputs.firemon_cloud_defense] section
        fcdDetails = data["outputs"]["firemon_cloud_defense"]

        # Parse Client ID
        if self.credentials_location == "CONFIG_FILE":
            clientId = fcdDetails["firemon_cloud_defense_client_id_value"]
        elif self.credentials_location == "AWS_SSM":
            clientId = self.get_credential_from_aws_ssm(
                fcdDetails["firemon_cloud_defense_client_id_value"],
                "firemon_cloud_defense_client_id_value"
            )
        elif self.credentials_location == "AWS_SECRETS_MANAGER":
            clientId = self.get_credential_from_aws_secrets_manager(
                fcdDetails["firemon_cloud_defense_client_id_value"],
                "firemon_cloud_defense_client_id_value"
            )
        # Parse API Key
        if self.credentials_location == "CONFIG_FILE":
            apiKey = fcdDetails["firemon_cloud_defense_api_key_value"]
        elif self.credentials_location == "AWS_SSM":
            apiKey = self.get_credential_from_aws_ssm(
                fcdDetails["firemon_cloud_defense_api_key_value"],
                "firemon_cloud_defense_api_key_value"
            )
        elif self.credentials_location == "AWS_SECRETS_MANAGER":
            apiKey = self.get_credential_from_aws_secrets_manager(
                fcdDetails["firemon_cloud_defense_api_key_value"],
                "firemon_cloud_defense_api_key_value"
            )

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not all(s for s in [clientId, apiKey]):
            print("An empty value was detected in '[outputs.firemon_cloud_defense]'. Review the TOML file and try again!")
            sys.exit(2)

        self.url = "https://collector.prod.disruptops.com/event"
        self.clientId = clientId
        self.apiKey = apiKey

    def write_findings(self, findings: list, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write!")
            exit(0)
        # Use another list comprehension to remove `ProductFields.AssetDetails` from non-Asset reporting outputs
        noDetails = [
            {**d, "ProductFields": {k: v for k, v in d["ProductFields"].items() if k != "AssetDetails"}} for d in findings
        ]
        del findings

        print(f"Writing {len(noDetails)} results to Firemon Cloud Defense (DisruptOps).")
        
        for finding in noDetails:
            r = requests.post(
                self.url, 
                data=json.dumps(finding),
                auth=(self.clientId, self.apiKey)
            )
            if r.status_code == 429:
                sleep(0.5)
            elif r.status_code == (400, 401, 403, 404):
                raise r.json()
        
    def get_credential_from_aws_ssm(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Systems Manager Parameter Store and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from SSM Parameter Store
        try:
            credential = ssm.get_parameter(
                Name=value,
                WithDecryption=True
            )["Parameter"]["Value"]
        except ClientError as e:
            raise e
        
        return credential
    
    def get_credential_from_aws_secrets_manager(self, value, configurationName):
        """
        Retrieves a TOML variable from AWS Secrets Manager and returns it
        """

        # Check that a value was provided
        if value == (None or ""):
            print(f"A value for {configurationName} was not provided. Fix the TOML file and run ElectricEye again.")
            sys.exit(2)

        # Retrieve the credential from AWS Secrets Manager
        try:
            credential = asm.get_secret_value(
                SecretId=value,
            )["SecretString"]
        except ClientError as e:
            raise e
        
        return credential

    # EOF