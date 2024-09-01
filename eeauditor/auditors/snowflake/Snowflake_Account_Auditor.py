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

import logging
from datetime import datetime, timezone, timedelta, UTC
from snowflake.connector import cursor
import snowflake.connector.errors as snowerrors
from check_register import CheckRegister
import base64
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SnowflakeAccountAuditor")

registry = CheckRegister()

def get_snowflake_password_policy(cache: dict, snowflakeCursor: cursor.SnowflakeCursor) -> dict:
    """
    Get the Snowflake password policy for the account from the ACCOUNT_USAGE.PASSWORD_POLICIES view.
    """
    response = cache.get("get_snowflake_password_policy")
    if response:
        return response
    
    query = "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES"
    
    cache["get_snowflake_password_policy"] = snowflakeCursor.execute(query).fetchall()

    return cache["get_snowflake_password_policy"]

@registry.register_check("snowflake.account")
def snowflake_account_enable_sso_check(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str, snowflakeAccountId: str, snowflakeRegion: str, snowflakeCursor: cursor.SnowflakeCursor
) -> dict:
    """[Snowflake.Account.1] Snowflake Accounts have Single Sign-On (SSO) enabled"""
    # ISO Time
    iso8601Time = datetime.now(UTC).replace(tzinfo=timezone.utc).isoformat()
    
    # Get the SSO configuration for the account by retrieving all INTEGRATIONS and filtering for the types for OAuth and SAML
    query = "SHOW INTEGRATIONS"
    try:
        q = snowflakeCursor.execute(query).fetchall()
    except snowerrors.ProgrammingError as e:
        logger.warning(f"An error occurred when executing the query: {e}")
        q = []

    ssoCheck = [integ for integ in q if "saml" in str(integ["type"]).lower() or "oauth" in str(integ["type"]).lower()]

    # B64 encode all of the details for the Asset
    assetJson = json.dumps(ssoCheck,default=str).encode("utf-8")
    assetB64 = base64.b64encode(assetJson)

    # this is a passing check
    if ssoCheck:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-sso-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "INFORMATIONAL"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.1] Snowflake Accounts have Single Sign-On (SSO) enabled",
            "Description": f"Snowflake account {snowflakeAccountId} has Single Sign-On (SSO) enabled either via SAML or External OAUTH.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for setting up federated authentication or SSO in Snowflake refer to the Overview of federated authentication and SSO section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-overview"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Snowflake",
                "ProviderType": "SaaS",
                "ProviderAccountId": snowflakeAccountId,
                "AssetRegion": snowflakeRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Snowflake Account",
                "AssetComponent": "Account"
            },
            "Resources": [
                {
                    "Type": "SnowflakeAccount",
                    "Id": snowflakeAccountId,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-6",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AC-19",
                    "NIST SP 800-53 Rev. 4 AC-24",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 PE-2",
                    "NIST SP 800-53 Rev. 4 PS-3",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.7.1.1",
                    "ISO 27001:2013 A.9.2.1"
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.1"
                ]
            },
            "Workflow": {"Status": "RESOLVED"},
            "RecordState": "ARCHIVED"
        }
        yield finding
    else:
        finding = {
            "SchemaVersion": "2018-10-08",
            "Id": f"{snowflakeAccountId}/snowflake-account-sso-enabled-check",
            "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
            "GeneratorId": snowflakeAccountId,
            "AwsAccountId": awsAccountId,
            "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
            "FirstObservedAt": iso8601Time,
            "CreatedAt": iso8601Time,
            "UpdatedAt": iso8601Time,
            "Severity": {"Label": "MEDIUM"},
            "Confidence": 99,
            "Title": "[Snowflake.Account.1] Snowflake Accounts have Single Sign-On (SSO) enabled",
            "Description": f"Snowflake account {snowflakeAccountId} does not have Single Sign-On (SSO) enabled neither via SAML nor External OAUTH. Federated authentication enables users to connect to Snowflake using secure SSO (single sign-on). With SSO enabled, users authenticate through an external (SAML 2.0-compliant or OAuth 2.0) identity provider (IdP). Once authenticated by an IdP, users can access their Snowflake account for the duration of their IdP session without having to authenticate to Snowflake again. Users can choose to initiate their sessions from within the interface provided by the IdP or directly in Snowflake. Configuring your Snowflake authentication so that users can log in using SSO reduces the attack surface for your organization because users only log in once across multiple applications and do not have to manage a separate set of credentials for their Snowflake account.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on best practices for setting up federated authentication or SSO in Snowflake refer to the Overview of federated authentication and SSO section of the Snowflake Documentation Portal.",
                    "Url": "https://docs.snowflake.com/en/user-guide/admin-security-fed-auth-overview"
                }
            },
            "ProductFields": {
                "ProductName": "ElectricEye",
                "Provider": "Snowflake",
                "ProviderType": "SaaS",
                "ProviderAccountId": snowflakeAccountId,
                "AssetRegion": snowflakeRegion,
                "AssetDetails": assetB64,
                "AssetClass": "Management & Governance",
                "AssetService": "Snowflake Account",
                "AssetComponent": "Account"
            },
            "Resources": [
                {
                    "Type": "SnowflakeAccount",
                    "Id": snowflakeAccountId,
                    "Partition": awsPartition,
                    "Region": awsRegion
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    "NIST CSF V1.1 PR.AC-6",
                    "NIST SP 800-53 Rev. 4 AC-1",
                    "NIST SP 800-53 Rev. 4 AC-2",
                    "NIST SP 800-53 Rev. 4 AC-3",
                    "NIST SP 800-53 Rev. 4 AC-16",
                    "NIST SP 800-53 Rev. 4 AC-19",
                    "NIST SP 800-53 Rev. 4 AC-24",
                    "NIST SP 800-53 Rev. 4 IA-1",
                    "NIST SP 800-53 Rev. 4 IA-2",
                    "NIST SP 800-53 Rev. 4 IA-4",
                    "NIST SP 800-53 Rev. 4 IA-5",
                    "NIST SP 800-53 Rev. 4 IA-8",
                    "NIST SP 800-53 Rev. 4 PE-2",
                    "NIST SP 800-53 Rev. 4 PS-3",
                    "AICPA TSC CC6.1",
                    "ISO 27001:2013 A.7.1.1",
                    "ISO 27001:2013 A.9.2.1"
                    "CIS Snowflake Foundations Benchmark V1.0.0 1.1"
                ]
            },
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE"
        }
        yield finding