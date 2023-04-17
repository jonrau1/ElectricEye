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

registry = CheckRegister()

@registry.register_check('github')
def github_placeholder(awsAccountId: str, awsRegion: str, awsPartition: str, github_pat: str, github_organization_id: str) -> dict:
    """[SSPM.GitHub.1] ElectricEye Placeholder GitHub Check"""

    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"placeholder-github-finding",
        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
        "GeneratorId": f"placeholder-github-finding",
        "AwsAccountId": awsAccountId,
        "Types": ["Software and Configuration Checks"],
        "FirstObservedAt": iso8601Time,
        "CreatedAt": iso8601Time,
        "UpdatedAt": iso8601Time,
        "Severity": {"Label": "INFORMATIONAL"},
        "Confidence": 99,
        "Title": "[SSPM.GitHub.1] ElectricEye Placeholder GitHub Check",
        "Description": "PLACEHOLDER FAKE FINDING",
        "Remediation": {
            "Recommendation": {
                "Text": "PLACEHOLDER FAKE FINDING",
                "Url": "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html",
            }
        },
        "ProductFields": {"Product Name": "ElectricEye"},
        "Resources": [
            {
                "Type": "GitHubOrganization",
                "Id": f"GitHubOrganization",
                "Partition": awsPartition,
                "Region": awsRegion
            }
        ],
        "Compliance": {
            "Status": "PASSED",
            "RelatedRequirements": [
                "NIST CSF PR.DS-1",
                "NIST SP 800-53 MP-8",
                "NIST SP 800-53 SC-12",
                "NIST SP 800-53 SC-28",
                "AICPA TSC CC6.1",
                "ISO 27001:2013 A.8.2.3",
            ],
        },
        "Workflow": {"Status": "RESOLVED"},
        "RecordState": "ARCHIVED",
    }
    yield finding    

###