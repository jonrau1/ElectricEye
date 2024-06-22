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

import datetime
from check_register import CheckRegister
import base64
import json

registry = CheckRegister()

def list_q_biz_apps(cache, session):
    response = cache.get("list_q_biz_apps")

    if response:
        return response
    
    qBizApps = []
    qbusiness = session.client("qbusiness")
    for app in qbusiness.list_applications()["applications"]:
        qBizApps.append(
            qbusiness.get_application(applicationId=app["applicationId"])
        )
    
    cache["list_q_biz_apps"] = qBizApps
    return cache["list_q_biz_apps"]

@registry.register_check("bedrock")
def q_business_app_audit_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[QBusiness.1] Amazon Q Business applications should be monitored for usage"""
    # ISO time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    # loop work groups from cache
    for qapp in list_q_biz_apps(cache, session):
        # B64 encode all of the details for the Asset
        assetJson = json.dumps(qapp,default=str).encode("utf-8")
        assetB64 = base64.b64encode(assetJson)

        displayName = qapp["displayName"]
        applicationId = qapp["applicationId"]
        applicationArn = qapp["applicationArn"]
        
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{applicationArn}/q-business-app-usage-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": applicationArn,
            "AwsAccountId": awsAccountId,
            "Types": [
                "Software and Configuration Checks/AWS Security Best Practices",
                "Effects/Data Exposure"
            ],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[QBusiness.1] Amazon Q Business applications should be monitored for usage",
            "Description": f"Amazon Q Business application {displayName} (ID: {applicationId}) is currently in use. Amazon Q Business is a fully managed, generative-AI powered assistant that you can configure to answer questions, provide summaries, generate content, and complete tasks based on your enterprise data. It allows end users to receive immediate, permissions-aware responses from enterprise data sources with citations, for use cases such as IT, HR, and benefits help desks. This finding is informational only and requires no further action.",
            "Remediation": {
                "Recommendation": {
                    "Text": "As the first step towards creating a generative artificial intelligence (AI) assistant, you configure an application. Then, you select and create a retriever, and also connect any data sources. After this, you grant end user access to users to interact with an application using the preferred identity provider, AWS IAM Identity Center. Your authorized users interact with your application through the web experience. You share the endpoint URL of your web experience with your users, who open the URL and are authenticated before they can start asking questions in your assistant application. The endpoint URL can be found in your web experience settings when selecting your application in the console.",
                    "Url": "https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/create-application.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Artificial Intelligence",
                "AssetService": "Amazon Q Business",
                "AssetComponent": "Application"
            },
            "Resources": [
                {
                    "Type": "AwsQBusinessApplication",
                    "Id": applicationArn,
                    "Partition": awsPartition,
                    "Region": awsRegion,
                    "Details": {
                        "Other": {
                            "displayName": displayName,
                            "applicationId": applicationId
                        }
                    }
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 ID.AM-2",
                    "NIST SP 800-53 Rev. 4 CM-8",
                    "NIST SP 800-53 Rev. 4 PM-5",
                    "AICPA TSC CC3.2",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.8.1.1",
                    "ISO 27001:2013 A.8.1.2",
                    "ISO 27001:2013 A.12.5.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding

## EOF