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

def get_findings(cache, session, awsAccountId):
    securityhub = session.client("securityhub")
    response = cache.get("get_findings")
    if response:
        return response
    cache["get_findings"] = securityhub.get_findings(
        Filters={
            # look for findings that belong to current account
            # will help deconflict checks run in a master account
            "AwsAccountId": [{"Value": awsAccountId, "Comparison": "EQUALS"}],
            # look for high or critical severity findings
            "SeverityLabel": [
                {"Value": "HIGH", "Comparison": "EQUALS"},
                {"Value": "CRITICAL", "Comparison": "EQUALS"},
            ],
            # look for AWS security hub integrations
            # company can be AWS or Amazon depending on service
            "CompanyName": [
                {"Value": "AWS", "Comparison": "EQUALS"},
                {"Value": "Amazon", "Comparison": "EQUALS"},
            ],
            # check for Active Records
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        },
        SortCriteria=[{"Field": "SeverityLabel", "SortOrder": "asc"}],
        MaxResults=100,
    )
    return cache["get_findings"]


@registry.register_check("securityhub")
def high_critical_findings(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services"""
    getFindings = get_findings(cache, session, awsAccountId)
    # B64 encode all of the details for the Asset
    assetJson = json.dumps(getFindings,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)
    generatorId = str(getFindings["ResponseMetadata"]["RequestId"])
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    if not getFindings["Findings"]:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": "high-critical-findings-located/" + awsAccountId,
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "FirstObservedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services",
            "Description": "High or critical findings were not found in the Security Hub hub for AWS account "
            + awsAccountId,
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on findings refer to the Findings in AWS Security Hub in the AWS Security Hub User Guide",
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "AWS Security Hub",
                "AssetComponent": "Findings"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Security_Hub_High_Critical_Findings",
                    "Partition": "aws",
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": "high-critical-findings-located/" + awsAccountId,
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": generatorId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "FirstObservedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[SecurityHub.1] Security Hub should not have active high or critical severity findings from AWS services",
            "Description": "High or critical findings were found in the Security Hub hub for AWS account "
            + awsAccountId,
            "Remediation": {
                "Recommendation": {
                    "Text": "For more information on findings refer to the Findings in AWS Security Hub in the AWS Security Hub User Guide",
                    "Url": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings.html"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "AWS",
                "ProviderType": "CSP",
                "ProviderAccountId": awsAccountId,
                "AssetRegion": awsRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Security Services",
                "AssetService": "AWS Security Hub",
                "AssetComponent": "Findings"
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"{awsPartition.upper()}::::Account:{awsAccountId}/AWS_Security_Hub_High_Critical_Findings",
                    "Partition": "aws",
                    "Region": awsRegion,
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 DE.AE-2",
                    "NIST SP 800-53 Rev. 4 AU-6",
                    "NIST SP 800-53 Rev. 4 CA-7",
                    "NIST SP 800-53 Rev. 4 IR-4",
                    "NIST SP 800-53 Rev. 4 SI-4",
                    "AICPA TSC CC7.2",
                    "ISO 27001:2013 A.12.4.1",
                    "ISO 27001:2013 A.16.1.1",
                    "ISO 27001:2013 A.16.1.4"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding