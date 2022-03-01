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
import os
import boto3
import requests
import pymongo
from processor.outputs.output_base import ElectricEyeOutput

ssm = boto3.client("ssm")

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "docdb"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        # Ensure that the required variables are present
        try:
            mongoUname = os.environ["MONGODB_USERNAME"]
            if mongoUname == ("placeholder" or None):
                print("Missing required MongoDB parameters")
        except KeyError:
            print("Missing required MongoDB parameters")

        try:
            mongoHostname = os.environ["MONGODB_HOSTNAME"]
            if mongoHostname == ("placeholder" or None):
                print("Missing required MongoDB parameters")
        except KeyError:
            print("Missing required MongoDB parameters")

        try:
            mongoPwParam = os.environ["MONGODB_PASSWORD_PARAMETER"]
            if mongoPwParam == ("placeholder" or None):
                print("Missing required MongoDB parameters")
        except KeyError:
            print("Missing required MongoDB parameters")

        # pull out the MongoDB Password from SSM
        mongoPw = str(ssm.get_parameter(Name=mongoPwParam)["Parameter"]["Value"])

        # Download the latest AWS Mongo TLS cert bundle
        url = "https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem"
        r = requests.get(url)

        print(f"Downloaded CA bundle")
        # Write it to where the output is happening
        with open("./rds-combined-ca-bundle.pem", "wb") as f:
            f.write(r.content)

        mongoTlsCertPath = "./rds-combined-ca-bundle.pem"
        # Build hostname - these are the default options for TLS sign-on into Mongo
        fullMongoHost = f"mongodb://{mongoUname}:{mongoPw}@{mongoHostname}:27017/?ssl=true&ssl_ca_certs={mongoTlsCertPath}&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false"

        print(f"Writing {len(findings)} findings to MongoDB")
        try:
            mongoConn = pymongo.MongoClient(fullMongoHost)
        except Exception as e:
            raise e

        print(f"Connected to MongoDB succesfully with {mongoConn}")

        eeMongoDb = mongoConn["ElectricEye"]

        mycol = eeMongoDb["ElectricEye-Findings"]

        # write to mongo in chunks of 40 using `insert_many()` method
        for i in range(0, len(findings), 40):
            # here is where the fun begins
            chunked = findings[i:i + 40]

            try:
                mycol.insert_many(chunked)
            except Exception as e:
                print(e)

        return True