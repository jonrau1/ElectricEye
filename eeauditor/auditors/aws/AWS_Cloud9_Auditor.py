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

@registry.register_check("cloud9")
def cloud9_ssm_access_check(cache: dict, session, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Cloud9.1] Cloud9 Environments should be accessed using Session Manager"""
    cloud9 = session.client("cloud9")
    paginator = cloud9.get_paginator("list_environments")
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    iterator = paginator.paginate()
    for page in iterator:
        for e in page["environmentIds"]:
            for env in cloud9.describe_environments(environmentIds=[e])["environments"]:
                c9Arn = str(env["arn"])
                c9Name = str(env["name"])
                # This is a failing check - SSM gives you private connection
                try:
                    connectEnv = str(env["connectionType"])
                except:
                    connectEnv = 'NONE_FOUND'
                # Try again
                if connectEnv != "CONNECT_SSM":
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": c9Arn + "/cloud9-ssm-access-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": c9Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "MEDIUM"},
                        "Confidence": 99,
                        "Title": "[Cloud9.1] Cloud9 Environments should be accessed using Session Manager",
                        "Description": "Cloud9 Environments "
                        + c9Name
                        + " is not using Session Manager Access. Refer to the remediation instructions to remediate this behavior",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "A no-ingress EC2 instance that's created for an EC2 environment enables AWS Cloud9 to connect to its Amazon EC2 instance without the need to open any inbound ports on that instance. To configure this see the Accessing no-ingress EC2 instances with AWS Systems Manager in the AWS Cloud 9 User Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/cloud9/latest/user-guide/ec2-ssm.html"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloud9Environment",
                                "Id": c9Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "Cloud9Name": c9Name
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "FAILED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                            ],
                        },
                        "Workflow": {"Status": "NEW"},
                        "RecordState": "ACTIVE"
                    }
                    yield finding
                else:
                    finding = {
                        "SchemaVersion": "2018-10-08",
                        "Id": c9Arn + "/cloud9-ssm-access-check",
                        "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                        "GeneratorId": c9Arn,
                        "AwsAccountId": awsAccountId,
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": iso8601Time,
                        "CreatedAt": iso8601Time,
                        "UpdatedAt": iso8601Time,
                        "Severity": {"Label": "INFORMATIONAL"},
                        "Confidence": 99,
                        "Title": "[Cloud9.1] Cloud9 Environments should be accessed using Session Manager",
                        "Description": "Cloud9 Environments "
                        + c9Name
                        + " is using Session Manager Access.",
                        "Remediation": {
                            "Recommendation": {
                                "Text": "A no-ingress EC2 instance that's created for an EC2 environment enables AWS Cloud9 to connect to its Amazon EC2 instance without the need to open any inbound ports on that instance. To configure this see the Accessing no-ingress EC2 instances with AWS Systems Manager in the AWS Cloud 9 User Guide for more information.",
                                "Url": "https://docs.aws.amazon.com/cloud9/latest/user-guide/ec2-ssm.html"
                            }
                        },
                        "ProductFields": {"Product Name": "ElectricEye"},
                        "Resources": [
                            {
                                "Type": "AwsCloud9Environment",
                                "Id": c9Arn,
                                "Partition": awsPartition,
                                "Region": awsRegion,
                                "Details": {
                                    "Other": {
                                        "Cloud9Name": c9Name
                                    }
                                }
                            }
                        ],
                        "Compliance": {
                            "Status": "PASSED",
                            "RelatedRequirements": [
                                "NIST CSF V1.1 PR.AC-3",
                                "NIST SP 800-53 Rev. 4 AC-1",
                                "NIST SP 800-53 Rev. 4 AC-17",
                                "NIST SP 800-53 Rev. 4 AC-19",
                                "NIST SP 800-53 Rev. 4 AC-20",
                                "NIST SP 800-53 Rev. 4 SC-15",
                                "AICPA TSC CC6.6",
                                "ISO 27001:2013 A.6.2.1",
                                "ISO 27001:2013 A.6.2.2",
                                "ISO 27001:2013 A.11.2.6",
                                "ISO 27001:2013 A.13.1.1",
                                "ISO 27001:2013 A.13.2.1",
                            ]
                        },
                        "Workflow": {"Status": "RESOLVED"},
                        "RecordState": "ARCHIVED"
                    }
                    yield finding