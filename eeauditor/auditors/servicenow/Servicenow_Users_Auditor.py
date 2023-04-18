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
import pysnow
import os
from check_register import CheckRegister

registry = CheckRegister()

SNOW_INSTANCE_NAME = os.environ["SNOW_INSTANCE_NAME"]
SNOW_SSPM_USERNAME = os.environ["SNOW_SSPM_USERNAME"]
SNOW_SSPM_PASSWORD = os.environ["SNOW_SSPM_PASSWORD"]
SNOW_FAILED_LOGIN_BREACHING_RATE = os.environ["SNOW_FAILED_LOGIN_BREACHING_RATE"]

def get_servicenow_users(cache: dict):
    """
    Pulls the entire Users table
    """
    response = cache.get("get_servicenow_users")
    if response:
        return response
    
    # Will need to create the pysnow.Client object everywhere - doesn't appear to be thread-safe
    snow = pysnow.Client(
        instance=SNOW_INSTANCE_NAME,
        user=SNOW_SSPM_USERNAME,
        password=SNOW_SSPM_PASSWORD
    )

    userResource = snow.resource(api_path='/table/sys_user')
    allUsers = userResource.get().all()
    
    cache["get_servicenow_users"] = allUsers

    return cache["get_servicenow_users"]

@registry.register_check("servicenow.users")
def servicenow_sspm_active_user_mfa_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.Users.1] Active users should have multi-factor authentication enabled
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for user in get_servicenow_users(cache):
        userId = str(user["sys_id"])
        userName = str(user["user_name"])
        roles = str(user["roles"])
        title = str(user["title"])
        email = str(user["email"])
        # Skip web services / integration "users" these are for automation it seems
        # TODO: Confirm hypothesis?
        if (user["web_service_access_only"] or user["internal_integration_user"]) == "true":
            continue
        # skip inactive users
        if user["active"] == "false":
            continue
        if user["enable_multifactor_authn"] == "false":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "HIGH"},
                "Confidence": 99,
                "Title": "[SSPM.Servicenow.Users.1] Active users should have multi-factor authentication enabled",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} does not have multi-factor authentication (MFA) enabled. MFA, also known as two-step verification, is a security requirement that users enter more than one set of credentials to access an instance. While passwords protect digital assets, they are simply not enough. Expert cybercriminals try to actively find passwords. By discovering one password, access can potentially be gained to multiple accounts for which you might have reused the password. Multi-factor authentication acts as an additional layer of security to prevent unauthorized users from accessing these accounts, even when the password has been stolen. Businesses use multi-factor authentication to validate user identities and provide quick and convenient access to authorized users. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up MFA for Users refer to the MFA activation, supported methods, and workflow section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/integrate/authentication/concept/c_MultifactorAuthentication.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
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
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-mfa-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-mfa-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SSPM.Servicenow.Users.1] Active users should have multi-factor authentication enabled",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} has multi-factor authentication (MFA) enabled.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on setting up MFA for Users refer to the MFA activation, supported methods, and workflow section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/integrate/authentication/concept/c_MultifactorAuthentication.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
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

@registry.register_check("servicenow.users")
def servicenow_sspm_active_user_failed_login_audits_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.Users.2] Active users with more than {SNOW_FAILED_LOGIN_BREACHING_RATE} failed login attempts should be audited
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for user in get_servicenow_users(cache):
        userId = str(user["sys_id"])
        userName = str(user["user_name"])
        roles = str(user["roles"])
        title = str(user["title"])
        email = str(user["email"])
        # Skip web services / integration "users" these are for automation it seems
        # TODO: Confirm hypothesis?
        if (user["web_service_access_only"] or user["internal_integration_user"]) == "true":
            continue
        # skip inactive users
        if user["active"] == "false":
            continue
        # Attempt to read "failed_attempts" into an int to compare to `SNOW_FAILED_LOGIN_BREACHING_RATE` - ValueError catch to set 0
        try:
            failedAttempts = int(user["failed_attempts"])
        except ValueError:
            failedAttempts = 0
        # This is a failing check
        if failedAttempts >= int(SNOW_FAILED_LOGIN_BREACHING_RATE):
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-failed-attempt-audit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-failed-attempt-audit-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": f"[SSPM.Servicenow.Users.2] Active users with more than {SNOW_FAILED_LOGIN_BREACHING_RATE} failed login attempts should be audited",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} has more than {SNOW_FAILED_LOGIN_BREACHING_RATE} failed login attempts and should be audited for potential indicators of compromise. While multiple failed login attempts are not necessarily a security risk on its own, as it can be an accessibility issue or legitimate forgetfulness, adversaries and other unauthorized users often attempt password spraying and credential stuffing attacks to gain illicit access to User accounts. Servicenow reccommends appplying a defined logging and auditing strategy so that you can identify and act on suspicious activity in a timely manner. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on failed login review best practices refer to the Managing failed login attempts (instance security hardening) section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/administer/security/reference/managing-failed-login-attempts.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-failed-attempt-audit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-failed-attempt-audit-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": f"[SSPM.Servicenow.Users.2] Active users with more than {SNOW_FAILED_LOGIN_BREACHING_RATE} failed login attempts should be audited",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} has none or less than {SNOW_FAILED_LOGIN_BREACHING_RATE} failed login attempts.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on failed login review best practices refer to the Managing failed login attempts (instance security hardening) section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/administer/security/reference/managing-failed-login-attempts.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

@registry.register_check("servicenow.users")
def servicenow_sspm_active_user_lockout_audit_check(cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str):
    """
    [SSPM.Servicenow.Users.3] Active users that are locked out should be audited
    """
    iso8601Time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    for user in get_servicenow_users(cache):
        userId = str(user["sys_id"])
        userName = str(user["user_name"])
        roles = str(user["roles"])
        title = str(user["title"])
        email = str(user["email"])
        # Skip web services / integration "users" these are for automation it seems
        # TODO: Confirm hypothesis?
        if (user["web_service_access_only"] or user["internal_integration_user"]) == "true":
            continue
        # skip inactive users
        if user["active"] == "false":
            continue
        # failing check
        if user["locked_out"] == "true":
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-locked-out-audit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-locked-out-audit-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "MEDIUM"},
                "Confidence": 99,
                "Title": "[SSPM.Servicenow.Users.3] Active users that are locked out should be audited",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} is locked out and should be audited for potential indicators of compromise. While multiple failed login attempts are not necessarily a security risk on its own, as it can be an accessibility issue or legitimate forgetfulness, adversaries and other unauthorized users often attempt password spraying and credential stuffing attacks to gain illicit access to User accounts. Servicenow reccommends appplying a defined logging and auditing strategy so that you can identify and act on suspicious activity in a timely manner. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on failed login review best practices refer to the Managing failed login attempts (instance security hardening) section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/administer/security/reference/managing-failed-login-attempts.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "FAILED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1"
                    ]
                },
                "Workflow": {"Status": "NEW"},
                "RecordState": "ACTIVE"
            }
            yield finding
        else:
            finding = {
                "SchemaVersion": "2018-10-08",
                "Id": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-locked-out-audit-check",
                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                "GeneratorId": f"servicenow/{SNOW_INSTANCE_NAME}/user/{userId}/snow-user-locked-out-audit-check",
                "AwsAccountId": awsAccountId,
                "Types": ["Software and Configuration Checks"],
                "FirstObservedAt": iso8601Time,
                "CreatedAt": iso8601Time,
                "UpdatedAt": iso8601Time,
                "Severity": {"Label": "INFORMATIONAL"},
                "Confidence": 99,
                "Title": "[SSPM.Servicenow.Users.3] Active users that are locked out should be audited",
                "Description": f"Servicenow user {userName} in instance {SNOW_INSTANCE_NAME} is locked out and should be audited for potential indicators of compromise. While multiple failed login attempts are not necessarily a security risk on its own, as it can be an accessibility issue or legitimate forgetfulness, adversaries and other unauthorized users often attempt password spraying and credential stuffing attacks to gain illicit access to User accounts. Servicenow reccommends appplying a defined logging and auditing strategy so that you can identify and act on suspicious activity in a timely manner. Refer to the remediation instructions if this configuration is not intended.",
                "Remediation": {
                    "Recommendation": {
                        "Text": "For more information on failed login review best practices refer to the Managing failed login attempts (instance security hardening) section of the Servicenow Product Documentation.",
                        "Url": "https://docs.servicenow.com/en-US/bundle/utah-platform-security/page/administer/security/reference/managing-failed-login-attempts.html",
                    }
                },
                "ProductFields": {
                    "ProductName": "ElectricEye",
                    "Provider": "Servicenow",
                    "AssetClass": "Identity & Access Management",
                    "AssetService": "Servicenow Users & Groups",
                    "AssetType": "Servicenow User"
                },
                "Resources": [
                    {
                        "Type": "ServicenowUser",
                        "Id": f"{SNOW_INSTANCE_NAME}/user/{userId}",
                        "Partition": awsPartition,
                        "Region": awsRegion,
                        "Details": {
                            "Other": {
                                "ServicenowInstance": SNOW_INSTANCE_NAME,
                                "SysId": userId,
                                "UserName": userName,
                                "Roles": roles,
                                "Title": title,
                                "Email": email
                            }
                        }
                    }
                ],
                "Compliance": {
                    "Status": "PASSED",
                    "RelatedRequirements": [
                        "NIST CSF ID.RA-3",
                        "NIST CSF DE.CM-7",
                        "NIST SP 800-53 AU-12",
                        "NIST SP 800-53 CA-7",
                        "NIST SP 800-53 CM-3",
                        "NIST SP 800-53 CM-8",
                        "NIST SP 800-53 PE-3",
                        "NIST SP 800-53 PE-6",
                        "NIST SP 800-53 PE-20",
                        "NIST SP 800-53 PM-12",
                        "NIST SP 800-53 PM-16",
                        "NIST SP 800-53 RA-3",
                        "NIST SP 800-53 SI-4",
                        "NIST SP 800-53 SI-5",
                        "AICPA TSC CC3.2",
                        "AICPA TSC CC7.2",
                        "ISO 27001:2013 Clause 6.1.2",
                        "ISO 27001:2013 A.12.4.1",
                        "ISO 27001:2013 A.14.2.7",
                        "ISO 27001:2013 A.15.2.1"
                    ]
                },
                "Workflow": {"Status": "RESOLVED"},
                "RecordState": "ARCHIVED"
            }
            yield finding

# End ??