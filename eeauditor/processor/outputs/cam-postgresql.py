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
import os
import json
import base64
import psycopg2 as psql
from botocore.exceptions import ClientError
from processor.outputs.output_base import ElectricEyeOutput

# Boto3 Clients
ssm = boto3.client("ssm")
asm = boto3.client("secretsmanager")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

@ElectricEyeOutput
class PostgresProvider(object):
    __provider__ = "cam_postgresql"

    def __init__(self):
        print("Preparing PostgreSQL credentials.")

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

        # Variable for the entire [outputs.postgresql] section
        postgresqlDetails = data["outputs"]["postgresql"]

        # Parse non-sensitive values
        tableName = postgresqlDetails["postgresql_table_name"]
        userName = postgresqlDetails["postgresql_username"]
        databaseName = postgresqlDetails["postgresql_database_name"]
        endpoint = postgresqlDetails["postgresql_endpoint"]
        port = postgresqlDetails["postgresql_port"]

        # Parse Password
        if self.credentials_location == "CONFIG_FILE":
            password = postgresqlDetails["postgresql_password_value"]
        elif self.credentials_location == "AWS_SSM":
            password = self.get_credential_from_aws_ssm(
                postgresqlDetails["postgresql_password_value"],
                "gcp_service_account_json_payload_value"
            )
        elif self.credentials_location == "AWS_SECRETS_MANAGER":
            password = self.get_credential_from_aws_secrets_manager(
                postgresqlDetails["postgresql_password_value"],
                "gcp_service_account_json_payload_value"
            )

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not all(s for s in [tableName, userName, databaseName, endpoint, port, password]):
            print("An empty value was detected in '[outputs.postgresql]'. Review the TOML file and try again!")
            sys.exit(2)
        
        self.tableName = tableName
        self.userName = userName
        self.databaseName = databaseName
        self.endpoint = endpoint
        self.port = port
        self.password = password

    def write_findings(self, findings: list, **kwargs):
        processedFindings = self.create_cam_format(findings)

        del findings

        try:
            engine = psql.connect(
                user=self.userName,
                database=self.databaseName,
                host=self.endpoint,
                port=self.port,
                password=self.password,
            )

            cursor = engine.cursor()

            # Create a Table based on the provided Table name that contains a Cloud Asset Management (CAM)
            # schema that mirrors cam_json. "asset_id" is the PRIMARY KEY and is derived from Resources.[*].Id
            # and the AssetDetails will be JSONB (json binary) format, everything else is TEXT or TIMESTAMP...
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.tableName}_cam (
                    asset_id TEXT PRIMARY KEY,
                    first_observed_at TIMESTAMP WITH TIME ZONE,
                    provider TEXT,
                    provider_type TEXT,
                    provider_account_id TEXT,
                    asset_region TEXT,
                    asset_details JSONB,
                    asset_class TEXT,
                    asset_service TEXT,
                    asset_component TEXT,
                    informational_severity_findings INTEGER,
                    low_severity_findings INTEGER,
                    medium_severity_findings INTEGER,
                    high_severity_findings INTEGER,
                    critical_severity_findings INTEGER
                )
            """)

            print(f"Attempting to write {len(processedFindings)} CAM entries to PostgreSQL.")
            for f in processedFindings:
                # The Finding ID is our primary key, on conflicts we will overwrite every single value for the specific ID except
                # for ASFF FirstObservedAt (first_observed_at) and ASFF CreatedAt (created_at) every other value will be preserved
                cursor.execute(f"""
                    INSERT INTO {self.tableName}_cam (asset_id, first_observed_at, provider, provider_type, provider_account_id, asset_region, asset_details, asset_class, asset_service, asset_component, informational_severity_findings, low_severity_findings, medium_severity_findings, high_severity_findings, critical_severity_findings)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (asset_id) DO UPDATE
                        SET product_arn = excluded.product_arn,
                            provider = excluded.provider,
                            provider_type = excluded.provider_type,
                            provider_account_id = excluded.provider_account_id,
                            asset_region = excluded.asset_region,
                            asset_details = excluded.asset_details,
                            asset_class = excluded.asset_class,
                            asset_service = excluded.asset_service,
                            asset_component = excluded.asset_component,
                            informational_severity_findings = excluded.informational_severity_findings,
                            low_severity_findings = excluded.low_severity_findings,
                            medium_severity_findings = excluded.medium_severity_findings,
                            high_severity_findings = excluded.high_severity_findings,
                            critical_severity_findings = excluded.critical_severity_findings,
                            first_observed_at = CASE
                                                    WHEN {self.tableName}_cam.first_observed_at < excluded.first_observed_at THEN {self.tableName}_cam.first_observed_at
                                                    ELSE excluded.first_observed_at
                                                END;
                    """,
                    (
                        f["AssetId"],
                        f["FirstObservedAt"],
                        f["Provider"],
                        f["ProviderType"],
                        f["ProviderAccountId"],
                        f["AssetRegion"],
                        f["AssetDetails"],
                        f["AssetClass"],
                        f["AssetService"],
                        f["AssetComponent"],
                        f["InformationalSeverityFindings"],
                        f["LowSeverityFindings"],
                        f["MediumSeverityFindings"],
                        f["HighSeverityFindings"],
                        f["CriticalSeverityFindings"]
                    )
                )

            # commit the changes
            engine.commit()
            # close communication with the postgres server (rds)
            cursor.close()
            
            print("Completed writing all CAM entries to PostgreSQL.")

        except psql.OperationalError as oe:
            print("Cannot connect to your PostgreSQL database. Review your network configuraions and database parameters and try again.")
            raise oe
        except Exception as e:
            raise e
        
        return True

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
    
    def create_cam_format(self, findings):
        """
        This function uses the list comprehension to base64 decode all `AssetDetails` and then takes a selective
        cross-section of unique per-asset details to be written to PostgreSQL
        """

        if len(findings) == 0:
            print("There are not any findings to write!")
            exit(0)

        # This list contains the CAM output
        cloudAssetManagementFindings = []
        # Create a new list from raw findings that base64 decodes `AssetDetails` where it is not None, if it is, just
        # use None and bring forward `ProductFields` where it is missing `AssetDetails`...which shouldn't happen
        print(f"Base64 decoding AssetDetails for {len(findings)} ElectricEye findings.")

        data = [
            {**d, "ProductFields": {**d["ProductFields"],
                "AssetDetails": json.loads(base64.b64decode(d["ProductFields"]["AssetDetails"]).decode("utf-8"))
                    if d["ProductFields"]["AssetDetails"] is not None
                    else None
            }} if "AssetDetails" in d["ProductFields"]
            else d
            for d in findings
        ]

        print(f"Completed base64 decoding for {len(data)} ElectricEye findings.")

        # This list will contain unique identifiers from `Resources.[*].Id`
        uniqueIds = set(item["Resources"][0]["Id"] for item in data)

        print(f"Processing Asset and Finding Summary data for {len(uniqueIds)} unique Assets.")

        for uid in uniqueIds:
            subData = [item for item in data if item["Resources"][0]["Id"] == uid]
            productFields = subData[0]["ProductFields"]
            infoSevFindings = lowSevFindings = medSevFindings = highSevFindings = critSevFindings = 0
            
            for item in subData:
                firstObserved = item["FirstObservedAt"]
                sevLabel = item["Severity"]["Label"]
                if sevLabel == "INFORMATIONAL":
                    infoSevFindings += 1
                elif sevLabel == "LOW":
                    lowSevFindings += 1
                elif sevLabel == "MEDIUM":
                    medSevFindings += 1
                elif sevLabel == "HIGH":
                    highSevFindings += 1
                elif sevLabel == "CRITICAL":
                    critSevFindings += 1
                
            
            cloudAssetManagementFindings.append(
                {
                    "AssetId": uid,
                    "FirstObservedAt": firstObserved,
                    "AssetClass": productFields.get("AssetClass", ""),
                    "AssetService": productFields.get("AssetService", ""),
                    "AssetComponent": productFields.get("AssetComponent", ""),
                    "Provider": productFields.get("Provider", ""),
                    "ProviderType": productFields.get("ProviderType", ""),
                    "ProviderAccountId": productFields.get("ProviderAccountId", ""),
                    "AssetRegion": productFields.get("AssetRegion", ""),
                    "AssetDetails": productFields.get("AssetDetails", ""),
                    "AssetClass": productFields.get("AssetClass", ""),
                    "AssetService": productFields.get("AssetService", ""),
                    "AssetComponent": productFields.get("AssetComponent", ""),
                    "InformationalSeverityFindings": infoSevFindings,
                    "LowSeverityFindings": lowSevFindings,
                    "MediumSeverityFindings": medSevFindings,
                    "HighSeverityFindings": highSevFindings,
                    "CriticalSeverityFindings": critSevFindings
                }
            )

        del findings
        del data
        del uniqueIds
        del subData

        return cloudAssetManagementFindings

## EOF

"""
mkdir ~/postgres-data
docker run -d --name my-postgres -e POSTGRES_PASSWORD=mysecretpassword -v ~/postgres-data:/var/lib/postgresql/data -p 5432:5432 postgres
"""