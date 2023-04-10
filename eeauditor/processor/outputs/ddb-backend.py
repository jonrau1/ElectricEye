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
import sys
import os
from processor.outputs.output_base import ElectricEyeOutput

# export DYNAMODB_TABLE_NAME='EEBackend'

@ElectricEyeOutput
class JsonProvider(object):
    __provider__ = "ddb_backend"

    def __init__(self):
        # DynamoDB Table Name
        try:
            ddbBackendTableName = os.environ["DYNAMODB_TABLE_NAME"]
        except KeyError:
            ddbBackendTableName = "placeholder"

        if ddbBackendTableName == ("placeholder" or None):
            print('Valid DynamoDB Table name was not provided!')
            sys.exit(2)
        else:
            self.db_name = ddbBackendTableName

    def write_findings(self, findings: list, **kwargs):

        print(f"Writing {len(findings)} findings to backend")

        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(self.db_name)

        # loop the findings and create a flatter structure - better for indexing without the nested lists
        for fi in findings:
            # Pull out the Finding ID just in case there is an underlying `KeyError` issue for debug
            findingId = fi["Id"]
            # some values may not always be present (Details, etc.) - change this to an empty Map
            try:
                resourceDetails = fi["Resources"][0]["Details"]
                if not resourceDetails:
                    resourceDetails = []
            except KeyError:
                resourceDetails = []
            # Partition data mapping
            partition = fi["Resources"][0]["Partition"]
            if partition == "aws":
                partitionName = "AWS Commercial"
            elif partition == "aws-us-gov":
                partitionName = "AWS GovCloud"
            elif partition == "aws-cn":
                partitionName = "AWS China"
            elif partition == "aws-isob":
                partitionName = "AWS ISOB" # Secret Region
            elif partition == "aws-iso":
                partitionName = "AWS ISO" # Top Secret Region

            try:
                # This format should map to FastAPI schema
                tableItem = {
                    "FindingId": findingId,
                    "Provider": "AWS",
                    "ProviderAccountId": fi["AwsAccountId"],
                    "CreatedAt": str(fi["CreatedAt"]),
                    "Severity": fi["Severity"]["Label"],
                    "Title": fi["Title"],
                    "Description": fi["Description"],
                    "RecommendationText": str(fi["Remediation"]["Recommendation"]["Text"]),
                    "RecommendationUrl": str(fi["Remediation"]["Recommendation"]["Url"]),
                    "ResourceType": str(fi["Resources"][0]["Type"]),
                    "ResourceId": str(fi["Resources"][0]["Id"]),
                    "ResourcePartition": partition,
                    "ResourceDetails": resourceDetails,
                    "FindingStatus": fi["Workflow"]["Status"],
                    "AuditReadinessMapping": fi["Compliance"]["RelatedRequirements"],
                    "AuditReadinessStatus": fi["Compliance"]["Status"].lower().capitalize()
                }
                # Write to DDB
                table.put_item(
                    Item=tableItem
                )
            except KeyError as e:
                print(f"Issue with Finding ID {findingId} due to missing value {e}")
                continue

        return True