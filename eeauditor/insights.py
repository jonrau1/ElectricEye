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

def create_sechub_insights():
    securityhub = boto3.client("securityhub")

    try:
        activeInsight = securityhub.create_insight(
            Name="ElectricEye Active Findings",
            Filters={
                "ProductFields": [
                    {"Key": "ProductName", "Value": "ElectricEye", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
            GroupByAttribute="ResourceType"
        )
        print(activeInsight)
    except Exception as e:
        print(e)

    try:
        remediatedInsight = securityhub.create_insight(
            Name="ElectricEye Remediated Findings",
            Filters={
                "ProductFields": [
                    {"Key": "ProductName", "Value": "ElectricEye", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ARCHIVED", "Comparison": "EQUALS"}]
            },
            GroupByAttribute="ResourceType"
        )
        print(remediatedInsight)
    except Exception as e:
        print(e)

    try:
        shodanInsight = securityhub.create_insight(
            Name="ElectricEye Shodan Findings",
            Filters={
                "ProductFields": [
                    {"Key": "ProductName", "Value": "ElectricEye", "Comparison": "EQUALS"},
                ],
                "ThreatIntelIndicatorSource": [{"Value": "Shodan.io", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
            GroupByAttribute="ResourceType"
        )
        print(shodanInsight)
    except Exception as e:
        print(e)

    try:
        easmInsight = securityhub.create_insight(
            Name="ElectricEye EASM",
            Filters={
                "ProductFields": [
                    {"Key": "ProductName", "Value": "ElectricEye", "Comparison": "EQUALS"},
                ],
                "Title": [{"Value": "[AttackSurface", "Comparison": "CONTAINS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
            GroupByAttribute="ResourceType"
        )
        print(easmInsight)
    except Exception as e:
        print(e)