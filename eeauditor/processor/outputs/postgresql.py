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
    __provider__ = "postgres"

    def __init__(self):
        print("Preparing PostgreSQL credentials.")

        # Get the absolute path of the current directory
        currentDir = os.path.abspath(os.path.dirname(__file__))
        # Go two directories back
        twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

        # TOML is located in /eeauditor/ directory
        tomlFile = f"{twoBack}/external_providers.toml"
        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Parse from [global] to determine credential location of PostgreSQL Password
        if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
            print("Invalid option for [global.credentials_location].")
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

        # Ensure that values are provided for all variable
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
        processedFindings = self.processing_findings_for_upset(findings)

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

            # Create a Table based on the provided Table name that contains a majority of the ASFF details
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.tableName} (
                    id TEXT PRIMARY KEY,
                    product_arn TEXT,
                    types TEXT[],
                    first_observed_at TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE,
                    updated_at TIMESTAMP WITH TIME ZONE,
                    severity_label TEXT,
                    title TEXT,
                    description TEXT,
                    remediation_recommendation_text TEXT,
                    remediation_recommendation_url TEXT,
                    product_name TEXT,
                    provider TEXT,
                    provider_type TEXT,
                    provider_account_id TEXT,
                    asset_region TEXT,
                    asset_class TEXT,
                    asset_service TEXT,
                    asset_component TEXT,
                    resource_id TEXT,
                    resource JSONB,
                    compliance_status TEXT,
                    compliance_related_requirements TEXT[],
                    workflow_status TEXT,
                    record_state TEXT
                )
            """)

            for f in processedFindings:

                cursor.execute(f"""
                    INSERT INTO {self.tableName} (id, product_arn, types, first_observed_at, created_at, updated_at, severity_label, title, description, remediation_recommendation_text, remediation_recommendation_url, product_name, provider, provider_type, provider_account_id, asset_region, asset_class, asset_service, asset_component, resource_id, resource, compliance_status, compliance_related_requirements, workflow_status, record_state)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE
                        SET product_arn = excluded.product_arn,
                            types = excluded.types,
                            updated_at = excluded.updated_at,
                            severity_label = excluded.severity_label,
                            title = excluded.title,
                            description = excluded.description,
                            remediation_recommendation_text = excluded.remediation_recommendation_text,
                            remediation_recommendation_url = excluded.remediation_recommendation_url,
                            product_name = excluded.product_name,
                            provider = excluded.provider,
                            provider_type = excluded.provider_type,
                            provider_account_id = excluded.provider_account_id,
                            asset_region = excluded.asset_region,
                            asset_class = excluded.asset_class,
                            asset_service = excluded.asset_service,
                            asset_component = excluded.asset_component,
                            resource_id = excluded.resource_id,
                            resource = excluded.resource,
                            compliance_status = excluded.compliance_status,
                            compliance_related_requirements = excluded.compliance_related_requirements,
                            workflow_status = excluded.workflow_status,
                            record_state = excluded.record_state,
                            first_observed_at = CASE
                                                    WHEN {self.tableName}.first_observed_at < excluded.first_observed_at THEN {self.tableName}.first_observed_at
                                                    ELSE excluded.first_observed_at
                                                END,
                            created_at = CASE
                                                WHEN {self.tableName}.created_at < excluded.created_at THEN {self.tableName}.created_at
                                                ELSE excluded.created_at
                                            END;
                    """,
                    (
                        f["Id"],
                        f["ProductArn"],
                        f["Types"],
                        f["FirstObservedAt"],
                        f["CreatedAt"],
                        f["UpdatedAt"],
                        f["SeverityLabel"],
                        f["Title"],
                        f["Description"],
                        f["RemedationRecommendationText"],
                        f["RemediationRecommendationUrl"],
                        f["ProductName"],
                        f["Provider"],
                        f["ProviderType"],
                        f["ProviderAccountId"],
                        f["AssetRegion"],
                        f["AssetClass"],
                        f["AssetService"],
                        f["AssetComponent"],
                        f["ResourceId"],
                        json.dumps(f["Resource"]),
                        f["ComplianceStatus"],
                        f["ComplianceRelatedRequirements"],
                        f["WorkflowStatus"],
                        f["RecordState"]
                    )
                )

            # commit the changes
            engine.commit()
            # close communication with the postgres server (rds)
            cursor.close()
            

        except psql.OperationalError as oe:
            print("Cannot connect to PostgreSQL! Review your Security Group settings and/or information provided to connect")
            raise oe
        except Exception as e:
            raise e 

        '''
        print(f"Writing {len(findings)} results to PostgreSQL")
        if (self.db_endpoint and self.db_port and self.db_username and self.db_password and self.db_name):
            try:
                # Connect to DB and create a Cursor
                engine = psql.connect(
                    database=self.db_name,
                    user=self.db_username,
                    password=self.db_password,
                    host=self.db_endpoint,
                    port=self.db_port
                )
                cursor = engine.cursor()
                
                # drop previously existing tables
                cursor.execute("""DROP TABLE IF EXISTS electriceye_findings""")
                engine.commit()
                
                # Create a new table for the ElectricEye findings. Everything is set as Text
                cursor.execute("""CREATE TABLE IF NOT EXISTS electriceye_findings( schemaversion TEXT, findingid TEXT, awsaccountid TEXT, productarn TEXT, generatorid TEXT, types TEXT, createdat TEXT, severitylabel TEXT, confidence TEXT, title TEXT, description TEXT, resourcetype TEXT, resourceid TEXT, resourceregion TEXT, resourcepartition TEXT, compliancestatus TEXT, compliancecontrols TEXT, workflowstatus TEXT, recordstate TEXT);""")

                for finding in findings:
                    # Basic parsing of ASFF to prepare for INSERT into PSQL
                    try:
                        awsaccountid = str(finding['AwsAccountId'])
                    except Exception as e:
                        if str(e) == "'AwsAccountId'":
                            awsaccountid = str(finding['awsAccountId'])
                        else:
                            continue
                    schemaversion = str(finding['SchemaVersion'])
                    findingid = str(finding['Id'])
                    productarn = str(finding['ProductArn'])
                    generatorid = str(finding['GeneratorId'])
                    types = str(finding['Types'][0])
                    createdat = str(finding['CreatedAt'])
                    severitylabel = str(finding['Severity']['Label'])
                    #TODO: Find which findings aren't mapped...
                    try:
                        confidence = str(finding['Confidence'])
                    except Exception:
                        confidence = '99'
                    title = str(finding['Title'])
                    description = str(finding['Description'])
                    resourcetype = str(finding['Resources'][0]['Type'])
                    resourceid = str(finding['Resources'][0]['Id'])
                    resourceregion = str(finding['Resources'][0]['Region'])
                    resourcepartition = str(finding['Resources'][0]['Partition'])
                    compliancestatus = str(finding['Compliance']['Status'])
                    #TODO: Find which findings aren't mapped...
                    try:
                        compliancecontrols = str(finding['Compliance']['RelatedRequirements'])
                    except Exception:
                        compliancecontrols = str('[]')
                    workflowstatus = str(finding['Workflow']['Status'])
                    recordstate = str(finding['RecordState'])

                    # Write into Postgres
                    cursor.execute("INSERT INTO electriceye_findings( schemaversion, findingid, awsaccountid, productarn, generatorid, types, createdat, severitylabel, confidence, title, description, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, compliancecontrols, workflowstatus, recordstate) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);", (schemaversion, findingid, awsaccountid, productarn, generatorid, types, createdat, severitylabel, confidence, title, description, resourcetype, resourceid, resourceregion, resourcepartition, compliancestatus, compliancecontrols, workflowstatus, recordstate))
                
                # commit the changes
                engine.commit()
                # close communication with the postgres server (rds)
                cursor.close()

            except psql.OperationalError:
                print("Cannot connect to PostgreSQL! Review your Security Group settings and/or information provided to connect")
                exit(2)
            except Exception:
                print("Another exception found " + Exception)
                exit(2)
        else:
            raise ValueError("Missing credentials or database parameters")
        '''
        
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
    
    def processing_findings_for_upset(self, findings):
        """
        This function will take in the "no assets" Findings list and parse out the specific values
        for upsertion into PostgreSQL
        """

        processedFindings = []

        for finding in findings:
            processedFindings.append(
                {
                    "Id": finding["Id"],
                    "ProductArn": finding["ProductArn"],
                    "Types": finding["Types"],
                    "FirstObservedAt": finding["FirstObservedAt"],
                    "CreatedAt": finding["CreatedAt"],
                    "UpdatedAt": finding["UpdatedAt"],
                    "SeverityLabel": finding["Severity"]["Label"],
                    "Title": finding["Title"],
                    "Description": finding["Description"],
                    "RemedationRecommendationText": finding["Remediation"]["Recommendation"]["Text"],
                    "RemediationRecommendationUrl": finding["Remediation"]["Recommendation"]["Url"],
                    "ProductName": finding["ProductFields"]["ProductName"],
                    "Provider": finding["ProductFields"]["Provider"],
                    "ProviderType": finding["ProductFields"]["ProviderType"],
                    "ProviderAccountId": finding["ProductFields"]["ProviderAccountId"],
                    "AssetRegion": finding["ProductFields"]["AssetRegion"],
                    "AssetClass": finding["ProductFields"]["AssetClass"],
                    "AssetService": finding["ProductFields"]["AssetService"],
                    "AssetComponent": finding["ProductFields"]["AssetComponent"],
                    "ResourceId": finding["Resources"][0]["Id"],
                    "Resource": finding["Resources"][0],
                    "ComplianceStatus": finding["Compliance"]["Status"],
                    "ComplianceRelatedRequirements": finding["Compliance"]["RelatedRequirements"],
                    "WorkflowStatus": finding["Workflow"]["Status"],
                    "RecordState": finding["RecordState"]
                }
            )

        print("Parsed out findings details for PostgreSQL.")

        return processedFindings

## EOF