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
import botocore
import datetime
from check_register import CheckRegister, accumulate_paged_results

registry = CheckRegister()

# boto3 clients
cognitoidp = boto3.client("cognito-idp")
wafv2 = boto3.client("wafv2")

# loop through Cognito User Pools
def list_user_pools(cache):
    response = cache.get("list_user_pools")
    if response:
        return response
    paginator = cognitoidp.get_paginator("list_user_pools")
    response_iterator = paginator.paginate(PaginationConfig={"PageSize": 60})
    cache["list_user_pools"] = accumulate_paged_results(
        page_iterator=response_iterator, key="UserPools"
    )
    return cache["list_user_pools"]

@registry.register_check("cognito-idp")
def cognitoidp_cis_password_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Cognito.1] Cognito user pools should have a password policy that meets or exceed AWS CIS Foundations Benchmark standards"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for userpools in list_user_pools(cache)["UserPools"]:
        userPoolId = str(userpools["Id"])
        response = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(response["UserPool"]["Arn"])
        userPoolId = str(response["UserPool"]["Id"])
        cognitoPwPolicy = response["UserPool"]["Policies"]["PasswordPolicy"]
        minLengthCheck = int(cognitoPwPolicy["MinimumLength"])
        uppercaseCheck = str(cognitoPwPolicy["RequireUppercase"])
        lowercaseCheck = str(cognitoPwPolicy["RequireLowercase"])
        numberCheck = str(cognitoPwPolicy["RequireNumbers"])
        symbolCheck = str(cognitoPwPolicy["RequireSymbols"])
        if (
            minLengthCheck >= 14
            and uppercaseCheck == "True"
            and lowercaseCheck == "True"
            and numberCheck == "True"
            and symbolCheck == "True"
        ):
            # this is a passing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-password-policy",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "awsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Cognito.1] Cognito user pools should have a password policy that meets or exceed AWS CIS Foundations Benchmark standards",
                "Description": f"Cognito user pool {userPoolArn} meets the password guidelines.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools have a password policy that meets or exceed AWS CIS Foundations Benchmark standards refer to the Adding User Pool Password Requirements section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding
        else:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-password-policy",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Cognito.1] Cognito user pools should have a password policy that meets or exceed AWS CIS Foundations Benchmark standards",
                "Description": f"Cognito user pool {userPoolArn} does not meet the password guidelines. Password policies, in part, enforce password complexity requirements, setting a password complexity policy increases account resiliency against brute force login attempts. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools have a password policy that meets or exceed AWS CIS Foundations Benchmark standards refer to the Adding User Pool Password Requirements section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding

@registry.register_check("cognito-idp")
def cognitoidp_temp_password_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Cognito.2] Cognito user pools should not allow temporary passwords to stay valid beyond 24 hours"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for userpools in list_user_pools(cache)["UserPools"]:
        userPoolId = str(userpools["Id"])
        response = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(response["UserPool"]["Arn"])
        userPoolId = str(response["UserPool"]["Id"])
        cognitoPwPolicy = response["UserPool"]["Policies"]["PasswordPolicy"]
        tempPwValidityCheck = int(cognitoPwPolicy["TemporaryPasswordValidityDays"])
        if tempPwValidityCheck > 1:
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-temp-password-life",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[Cognito.2] Cognito user pools should not allow temporary passwords to stay valid beyond 24 hours",
                "Description": f"Cognito user pool {userPoolArn} allows temporary passwords to stay valid beyond 24 hours. Password policies, in part, enforce password complexity requirements, setting a password complexity policy increases account resiliency against brute force login attempts. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To modify your Cognito user pool temporary password policy refer to the Authentication Flow for Users Created by Administrators or Developers section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-temp-password-life",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Cognito.2] Cognito user pools should not allow temporary passwords to stay valid beyond 24 hours",
                "Description": f"Cognito user pool {userPoolArn} does not allow temporary passwords to stay valid beyond 24 hours.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To modify your Cognito user pool temporary password policy refer to the Authentication Flow for Users Created by Administrators or Developers section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3",
                        "MITRE ATT&CK T1589",
                        "MITRE ATT&CK T1586"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cognito-idp")
def cognitoidp_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Cognito.3] Cognito user pools should enforce multi factor authentication (MFA)"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for userpools in list_user_pools(cache)["UserPools"]:
        userPoolId = str(userpools["Id"])
        # Get specific user pool info
        r = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(r["UserPool"]["Arn"])
        userPoolId = str(r["UserPool"]["Id"])
        mfaCheck = str(r["UserPool"]["MfaConfiguration"])
        if mfaCheck != "ON":
            # this is a failing check
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-mfa",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Cognito.3] Cognito user pools should enforce multi factor authentication (MFA)",
                "Description": f"Cognito user pool {userPoolArn} does not enforce multi factor authentication (MFA). AWS recommends enabling MFA for all accounts that have a console password. Enabling MFA provides increased security for console access because it requires the authenticating principal to possess a device that emits a time-sensitive key and have knowledge of a credential. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools enforce MFA refer to the Adding Multi-Factor Authentication (MFA) to a User Pool section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-mfa",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Cognito.3] Cognito user pools should enforce multi factor authentication (MFA)",
                "Description": f"Cognito user pool {userPoolArn} enforces multi factor authentication (MFA).",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools enforce MFA refer to the Adding Multi-Factor Authentication (MFA) to a User Pool section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF PR.AC-1",
                        "NIST SP 800-53 AC-1",
                        "NIST SP 800-53 AC-2",
                        "NIST SP 800-53 IA-1",
                        "NIST SP 800-53 IA-2",
                        "NIST SP 800-53 IA-3",
                        "NIST SP 800-53 IA-4",
                        "NIST SP 800-53 IA-5",
                        "NIST SP 800-53 IA-6",
                        "NIST SP 800-53 IA-7",
                        "NIST SP 800-53 IA-8",
                        "NIST SP 800-53 IA-9",
                        "NIST SP 800-53 IA-10",
                        "NIST SP 800-53 IA-11",
                        "AICPA TSC CC6.1",
                        "AICPA TSC CC6.2",
                        "ISO 27001:2013 A.9.2.1",
                        "ISO 27001:2013 A.9.2.2",
                        "ISO 27001:2013 A.9.2.3",
                        "ISO 27001:2013 A.9.2.4",
                        "ISO 27001:2013 A.9.2.6",
                        "ISO 27001:2013 A.9.3.1",
                        "ISO 27001:2013 A.9.4.2",
                        "ISO 27001:2013 A.9.4.3"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("cognito-idp")
def cognitoidp_waf_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str) -> dict:
    """[Cognito.4] Cognito user pools should be protected by AWS Web Application Firewall"""
    # ISO Time
    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    for userpools in list_user_pools(cache)["UserPools"]:
        userPoolId = str(userpools["Id"])
        # Get specific user pool info
        r = cognitoidp.describe_user_pool(UserPoolId=userPoolId)
        userPoolArn = str(r["UserPool"]["Arn"])
        # attempt to retrieve a WAFv2 WebACL for the resource - errors or other values are not given for a lack of coverage
        # so we end up having to create our own way to determine
        getacl = wafv2.get_web_acl_for_resource(ResourceArn=userPoolArn)
        try:
            coverage = getacl["WebACL"]["ARN"]
        except KeyError:
            coverage = False
        # this is a failing check
        if coverage == False:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-waf-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[Cognito.4] Cognito user pools should be protected by AWS Web Application Firewall",
                "Description": f"Cognito user pool {userPoolArn} is not protected by an AWS WAF Web ACL. For additional protection, you can use WAF to protect Amazon Cognito user pools from web-based attacks and unwanted bots. Cognito's integration with WAF enables you to define rules that enforce rate limits, gain visibility into the web traffic to your applications, and allow or block traffic to Cognito user pools based on business or security requirements, and optimize costs by controlling bot traffic. Refer to the remediation instructions to remediate this behavior.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools are protected by AWS WAF refer to the Associating an AWS WAF web ACL with a user pool section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        # this is a passing check
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"{userPoolArn}/cognito-user-pool-waf-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": userPoolId,
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[Cognito.4] Cognito user pools should be protected by AWS Web Application Firewall",
                "Description": f"Cognito user pool {userPoolArn} is protected by an AWS WAF Web ACL.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "To ensure you Cognito user pools are protected by AWS WAF refer to the Associating an AWS WAF web ACL with a user pool section of the Amazon Cognito Developer Guide",
                        "Url": "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html"
                    }
                },
                "ProductFields": {"Product Name": "ElectricEye"},
                "Resources": [
                    {
                        "Type": "AwsCognitoUserPool",
                        "Id": userPoolArn,
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {"Other": {"UserPoolId": userPoolId}}
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF DE.AE-2",
                        "NIST SP 800-53 AU-6",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 IR-4",
                        "NIST SP 800-53 SI-4",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.16.1.1",
                        "ISO 27001:2013 A.16.1.4",
                        "MITRE ATT&CK T1595",
                        "MITRE ATT&CK T1590",
                        "MITRE ATT&CK T1190"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding