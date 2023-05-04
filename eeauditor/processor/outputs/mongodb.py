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
import tomli
import os
import sys
import requests
import pymongo
from processor.outputs.output_base import ElectricEyeOutput

# Boto3 Clients
ssm = boto3.client("ssm")
asm = boto3.client("secretsmanager")

# These Constants define legitimate values for certain parameters within the external_providers.toml file
CREDENTIALS_LOCATION_CHOICES = ["AWS_SSM", "AWS_SECRETS_MANAGER", "CONFIG_FILE"]

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "mongodb"

    def __init__(self):
        print("Preparing MongoDB / AWS DocumentDB credentials and PEM files (as needed).")

        # Get the absolute path of the current directory
        currentDir = os.path.abspath(os.path.dirname(__file__))
        # Go two directories back to /eeauditor/
        twoBack = os.path.abspath(os.path.join(currentDir, "../../"))

        # TOML is located in /eeauditor/ directory
        tomlFile = f"{twoBack}/external_providers.toml"
        with open(tomlFile, "rb") as f:
            data = tomli.load(f)

        # Parse from [global] to determine credential location of MongoDB Password
        if data["global"]["credentials_location"] not in CREDENTIALS_LOCATION_CHOICES:
            print(f"Invalid option for [global.credentials_location]. Must be one of {str(CREDENTIALS_LOCATION_CHOICES)}.")
            sys.exit(2)
        self.credentials_location = data["global"]["credentials_location"]

        # Variable for the entire [outputs.mongodb] section
        mongodbDetails = data["outputs"]["mongodb"]

        # Retrieve the values that will always be there
        mongodbOnAwsDocDb = mongodbDetails["mongodb_using_aws_documentdb"]
        mongodbUsername = mongodbDetails["mongodb_username"]
        mongodbEndpoint = mongodbDetails["mongodb_endpoint"]
        mongodbPort = mongodbDetails["mongodb_port"]
        mongodbDatabaseName = mongodbDetails["mongodb_database_name"]
        mongodbCollectionName = mongodbDetails["mongodb_collection_name"]
        mongodbInsertManyChunkSize = mongodbDetails["mongodb_insert_many_chunk_size"]

        # Determine if a password if provided, and if so, retrieve it based on `credentials_location`
        if mongodbDetails["mongodb_password_in_use"] == True:
            self.usePassword = True
            # Parse Password
            if self.credentials_location == "CONFIG_FILE":
                password = mongodbDetails["mongodb_password_value"]
            elif self.credentials_location == "AWS_SSM":
                password = self.get_credential_from_aws_ssm(
                    mongodbDetails["mongodb_password_value"],
                    "mongodb_password_value"
                )
            elif self.credentials_location == "AWS_SECRETS_MANAGER":
                password = self.get_credential_from_aws_secrets_manager(
                    mongodbDetails["mongodb_password_value"],
                    "mongodb_password_value"
                )
        else:
            self.usePassword = False
            password = None
            # without a PW there is no user, 
            mongodbUsername = "none"

        # Determine if a TLS package for AWS DocumentDB needs to be downloaded
        if mongodbDetails["mongodb_aws_documentdb_tls_enabled"] == True:
            self.useTls = True
            # Download the latest AWS Mongo TLS cert bundle
            r = requests.get("https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem")
            print(f"Downloaded CA bundle")
            # Write it to where the output is happening
            with open("./global-bundle.pem", "wb") as f:
                f.write(r.content)
            mongoTlsCertPath = "./global-bundle.pem"
        else:
            mongoTlsCertPath = None
            self.useTls = False

        # Ensure that values are provided for all variable - use all() and a list comprehension to check the vars
        # empty strings will trigger `if not`
        if not all(
            s for s in [
                mongodbUsername, mongodbEndpoint, mongodbPort, mongodbDatabaseName, mongodbCollectionName, mongodbInsertManyChunkSize
                ]
            ):
            print("An empty value was detected in '[outputs.mongodb]'. Review the TOML file and try again!")
            sys.exit(2)

        self.usingAwsDocDb = mongodbOnAwsDocDb
        self.username = mongodbUsername
        self.endpoint = mongodbEndpoint
        self.port = mongodbPort
        self.dbName = mongodbDatabaseName
        self.collName = mongodbCollectionName
        self.chunkSize = mongodbInsertManyChunkSize
        self.password = password
        self.tlsPath = mongoTlsCertPath

    def write_findings(self, findings: list, output_file: str, **kwargs):
        if len(findings) == 0:
            print("There are not any findings to write!")
            exit(0)
        
        # There are different possible connection objects based on if Passwords are used and if TLS is enabled for AWS DocDB

        # Self-hosted, no password
        if (self.usePassword and self.usingAwsDocDb) == False:
            connectionString = f"mongodb://{self.endpoint}:{self.port}"
        # Self-hosted, with password
        if self.usePassword == True and self.usingAwsDocDb == False:
            connectionString = f"mongodb://{self.username}:{self.password}@{self.endpoint}:{self.port}"
        # AWS DocumentDB, TLS-Disabled
        if self.usingAwsDocDb == True and self.useTls == False:
            connectionString = f"mongodb://{self.username}:{self.password}@{self.endpoint}:{self.port}/?replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false"
        # AWS DocumentDB, TLS-Enabled
        if (self.usingAwsDocDb and self.useTls) == True:
            connectionString = f"mongodb://{self.username}:{self.password}@{self.endpoint}:{self.port}/?tls=true&tlsCAFile={self.tlsPath}&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false"
        
        # Attempt to create the connection object, database, and collection - if there is an issue with credentials or connectivity
        # then we will catch it here

        try:
            # Connect to MongoDB
            client = pymongo.MongoClient(connectionString)
            db = client[self.dbName]
            collection = db[self.collName]
        except pymongo.errors.ConnectionError as e:
            print(f"Connection or credential issue with MongoDB/AWS DocumentDB!")
            raise e

        print(f"Attempting to write {len(findings)} findings to MongoDB in {self.chunkSize} chunks")

        for i in range(0, len(findings), self.chunkSize):
            # here is where the fun begins
            chunked = findings[i:i + self.chunkSize]

            try:
                collection.insert_many(chunked)
            except pymongo.errors as e:
                print(f"Encountered an error during insert_many() operation: {e}")

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

# EOF